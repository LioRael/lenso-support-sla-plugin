//! PostgreSQL-backed Support SLA behavior for Lenso.

#![allow(clippy::items_after_test_module, clippy::ref_option)]

mod operator;
mod schema;
mod storage;

#[cfg(all(test, feature = "postgres-acceptance"))]
mod postgres_tests;

use std::{cell::RefCell, collections::BTreeSet, fmt, rc::Rc, time::Duration};

use lenso::prelude::{
    ActivateContext, Ctx, DeactivateContext, Lifecycle, PluginError, PluginResult, Port,
};
use lenso_auth_sdk::{
    ActorAssertion, ActorAssertionVerifier, ActorProjectionError, AssertionClock, TypedActor,
};
use lenso_capability_access_control as access;
use lenso_capability_access_control::{
    AccessControlInvocationError, CheckPermissionRequest, CheckPermissionRequestScope,
};
use lenso_capability_jobs as jobs;
use lenso_capability_organization_membership as membership;
use lenso_capability_organization_membership::{
    CheckMembershipRequest, OrganizationMembershipInvocationError,
};
use lenso_capability_secrets as secrets;
use lenso_capability_secrets::{ResolveRequest, SecretsInvocationError};
use lenso_capability_support_sla as sla;
use lenso_kernel::{PluginDependencies, RuntimeFailure};
use lenso_plugin_authoring_current::ManyPort;
use lenso_postgres_kit::OwnedPostgres;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use zeroize::Zeroizing;

use crate::storage::{DomainFailure, StorageError};

pub use operator::{SupportSlaOperator, SupportSlaOperatorError};

const DEPENDENCY_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_CALLERS: usize = 64;
const MAX_RECONCILE_BATCH: i64 = 200;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SupportSlaConfig {
    schema: String,
    database_url_secret: String,
    auth_issuer: String,
    auth_assertion_public_key: String,
    management_callers: Vec<String>,
    observer_callers: Vec<String>,
    worker_callers: Vec<String>,
    jobs_queue: String,
    reconciliation_interval_seconds: i64,
    max_reconcile_batch: i64,
}

impl SupportSlaConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        schema: impl Into<String>,
        database_url_secret: impl Into<String>,
        auth_issuer: impl Into<String>,
        auth_assertion_public_key: impl Into<String>,
        management_callers: Vec<String>,
        observer_callers: Vec<String>,
        worker_callers: Vec<String>,
        jobs_queue: impl Into<String>,
        reconciliation_interval_seconds: i64,
        max_reconcile_batch: i64,
    ) -> Result<Self, SupportSlaConfigError> {
        let value = Self {
            schema: schema.into(),
            database_url_secret: database_url_secret.into(),
            auth_issuer: auth_issuer.into(),
            auth_assertion_public_key: auth_assertion_public_key.into(),
            management_callers,
            observer_callers,
            worker_callers,
            jobs_queue: jobs_queue.into(),
            reconciliation_interval_seconds,
            max_reconcile_batch,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), SupportSlaConfigError> {
        schema::schema_plan(self.schema.clone())
            .map_err(|_| SupportSlaConfigError::InvalidSchema)?;
        if !valid_secret_reference(&self.database_url_secret) {
            return Err(SupportSlaConfigError::InvalidSecretReference);
        }
        if !valid_identifier(&self.auth_issuer, 256) {
            return Err(SupportSlaConfigError::InvalidAuthIssuer);
        }
        ActorAssertionVerifier::from_public_key_base64(
            self.auth_issuer.clone(),
            &self.auth_assertion_public_key,
        )
        .map_err(|_| SupportSlaConfigError::InvalidAuthPublicKey)?;
        if !valid_callers(&self.management_callers) {
            return Err(SupportSlaConfigError::InvalidManagementCallers);
        }
        if !valid_callers(&self.observer_callers) {
            return Err(SupportSlaConfigError::InvalidObserverCallers);
        }
        if !valid_callers(&self.worker_callers) {
            return Err(SupportSlaConfigError::InvalidWorkerCallers);
        }
        let management = self.management_callers.iter().collect::<BTreeSet<_>>();
        let observer = self.observer_callers.iter().collect::<BTreeSet<_>>();
        let worker = self.worker_callers.iter().collect::<BTreeSet<_>>();
        if !management.is_disjoint(&observer)
            || !management.is_disjoint(&worker)
            || !observer.is_disjoint(&worker)
        {
            return Err(SupportSlaConfigError::OverlappingCallers);
        }
        if !valid_jobs_name(&self.jobs_queue, 128) {
            return Err(SupportSlaConfigError::InvalidJobsQueue);
        }
        if !(30..=86_400).contains(&self.reconciliation_interval_seconds) {
            return Err(SupportSlaConfigError::InvalidReconciliationInterval);
        }
        if !(1..=MAX_RECONCILE_BATCH).contains(&self.max_reconcile_batch) {
            return Err(SupportSlaConfigError::InvalidReconcileBatch);
        }
        Ok(())
    }

    fn verifier(&self) -> Result<ActorAssertionVerifier, RuntimeFailure> {
        ActorAssertionVerifier::from_public_key_base64(
            self.auth_issuer.clone(),
            &self.auth_assertion_public_key,
        )
        .map_err(|_| RuntimeFailure::InvalidResolvedPlan {
            detail: "Support SLA Auth verification key is invalid".to_owned(),
        })
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum SupportSlaConfigError {
    #[error("invalid owned PostgreSQL schema")]
    InvalidSchema,
    #[error("invalid database URL secret reference")]
    InvalidSecretReference,
    #[error("invalid Auth issuer")]
    InvalidAuthIssuer,
    #[error("invalid Auth assertion public key")]
    InvalidAuthPublicKey,
    #[error("management_callers must contain 1 to 64 unique exact Instance keys")]
    InvalidManagementCallers,
    #[error("observer_callers must contain 1 to 64 unique exact Instance keys")]
    InvalidObserverCallers,
    #[error("worker_callers must contain 1 to 64 unique exact Instance keys")]
    InvalidWorkerCallers,
    #[error("management, observer, and worker callers must be disjoint")]
    OverlappingCallers,
    #[error("invalid Jobs queue")]
    InvalidJobsQueue,
    #[error("reconciliation interval must be between 30 and 86400 seconds")]
    InvalidReconciliationInterval,
    #[error("maximum reconcile batch must be between 1 and 200")]
    InvalidReconcileBatch,
}

fn validate_config(config: &SupportSlaConfig) -> Result<(), RuntimeFailure> {
    config
        .validate()
        .map_err(|error| RuntimeFailure::InvalidResolvedPlan {
            detail: format!("Support SLA configuration is invalid: {error}"),
        })
}

#[derive(Clone, Debug)]
struct PreparedSupportSla {
    postgres: OwnedPostgres,
}

#[lenso::plugin(
    lifecycle,
    configuration_schema = "configuration.schema.json",
    validate = validate_config
)]
#[derive(Clone)]
struct SupportSlaPlugin {
    #[config]
    config: SupportSlaConfig,
    secrets: Port<secrets::SecretsClient>,
    membership: Port<membership::OrganizationMembershipClient>,
    access: Port<access::AccessControlClient>,
    jobs: ManyPort<jobs::JobsClient>,
    prepared: Rc<RefCell<Option<PreparedSupportSla>>>,
}

impl fmt::Debug for SupportSlaPlugin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SupportSlaPlugin")
            .field("schema", &self.config.schema)
            .field("prepared", &self.prepared.borrow().is_some())
            .field(
                "management_caller_count",
                &self.config.management_callers.len(),
            )
            .field("observer_caller_count", &self.config.observer_callers.len())
            .field("worker_caller_count", &self.config.worker_callers.len())
            .field(
                "jobs_provider_count",
                &self.jobs.is_connected().then(|| self.jobs.len()),
            )
            .finish_non_exhaustive()
    }
}

#[lenso::provides(sla::SupportSla)]
impl SupportSlaPlugin {}

#[derive(Clone, Debug)]
struct Authorized {
    caller: String,
    actor: String,
}

#[derive(Debug)]
enum AuthorizationFailure {
    Unauthenticated,
    Forbidden,
    Runtime(RuntimeFailure),
}

impl SupportSlaPlugin {
    fn prepared(&self) -> Result<PreparedSupportSla, RuntimeFailure> {
        self.prepared
            .borrow()
            .clone()
            .ok_or_else(|| RuntimeFailure::PluginFailure {
                detail: "Support SLA Plugin is not prepared".to_owned(),
            })
    }

    async fn authorize_management(
        &self,
        context: &Ctx,
        operation: &str,
        organization_id: &str,
        permission: &str,
    ) -> Result<Authorized, AuthorizationFailure> {
        let caller = exact_caller(context, &self.config.management_callers)
            .ok_or(AuthorizationFailure::Forbidden)?;
        let actor = self
            .config
            .verifier()
            .map_err(AuthorizationFailure::Runtime)?
            .project_context::<SupportSlaActor>(context, sla::CAPABILITY_ID, operation, &UtcClock)
            .map_err(|_| AuthorizationFailure::Unauthenticated)?
            .subject;
        if !valid_identifier(organization_id, 512) || !valid_identifier(&actor, 512) {
            return Err(AuthorizationFailure::Forbidden);
        }
        let membership = self
            .membership
            .check_membership_with_context(
                context.clone(),
                CheckMembershipRequest {
                    organization_id: organization_id.to_owned(),
                    subject: actor.clone(),
                },
            )
            .await
            .map_err(|error| match error {
                OrganizationMembershipInvocationError::Runtime(error) => {
                    AuthorizationFailure::Runtime(error)
                }
                OrganizationMembershipInvocationError::Domain(_) => {
                    AuthorizationFailure::Runtime(RuntimeFailure::ProtocolViolation {
                        capability: membership::CAPABILITY_ID,
                    })
                }
            })?;
        if !membership.active {
            return Err(AuthorizationFailure::Forbidden);
        }
        let decision = self
            .access
            .check_permission_with_context(
                context.clone(),
                CheckPermissionRequest {
                    subject: actor.clone(),
                    scope: CheckPermissionRequestScope {
                        kind: "organization".to_owned(),
                        id: organization_id.to_owned(),
                    },
                    permission: permission.to_owned(),
                },
            )
            .await
            .map_err(|error| match error {
                AccessControlInvocationError::Runtime(error) => {
                    AuthorizationFailure::Runtime(error)
                }
                AccessControlInvocationError::Domain(_) => {
                    AuthorizationFailure::Runtime(RuntimeFailure::ProtocolViolation {
                        capability: access::CAPABILITY_ID,
                    })
                }
            })?;
        if !decision.allowed {
            return Err(AuthorizationFailure::Forbidden);
        }
        Ok(Authorized { caller, actor })
    }

    fn observer_caller(&self, context: &Ctx) -> Option<String> {
        exact_caller(context, &self.config.observer_callers)
    }

    fn worker_caller(&self, context: &Ctx) -> Option<String> {
        exact_caller(context, &self.config.worker_callers)
    }
}

macro_rules! management_auth {
    ($result:expr, $error:ident) => {
        match $result {
            Ok(value) => value,
            Err(AuthorizationFailure::Unauthenticated) => {
                return Err(PluginError::domain(sla::$error::Unauthenticated));
            }
            Err(AuthorizationFailure::Forbidden) => {
                return Err(PluginError::domain(sla::$error::Forbidden));
            }
            Err(AuthorizationFailure::Runtime(error)) => return Err(PluginError::runtime(error)),
        }
    };
}

macro_rules! mutation_failure {
    ($failure:expr, $error:ident) => {
        match $failure {
            DomainFailure::NotFound => sla::$error::NotFound,
            DomainFailure::Archived => sla::$error::Archived,
            DomainFailure::RevisionConflict => sla::$error::RevisionConflict,
            DomainFailure::IdempotencyConflict => sla::$error::IdempotencyConflict,
            DomainFailure::OperationInProgress => sla::$error::OperationInProgress,
            DomainFailure::AlreadyExists => sla::$error::AlreadyExists,
            _ => sla::$error::InvalidRequest,
        }
    };
}

macro_rules! read_failure {
    ($failure:expr, $error:ident) => {
        match $failure {
            DomainFailure::NotFound => sla::$error::NotFound,
            _ => sla::$error::InvalidRequest,
        }
    };
}

impl SupportSlaPlugin {
    async fn create_policy(
        &self,
        context: Ctx,
        request: sla::CreatePolicyRequest,
    ) -> PluginResult<sla::CreatePolicyResponse, sla::CreatePolicyError> {
        let auth = management_auth!(
            self.authorize_management(
                &context,
                sla::CREATE_POLICY_OPERATION,
                &request.organization_id,
                "support.sla.manage",
            )
            .await,
            CreatePolicyError
        );
        let targets = parse_targets(&request.targets)
            .ok_or_else(|| PluginError::domain(sla::CreatePolicyError::InvalidRequest))?;
        if !valid_command_fields(
            &request.idempotency_key,
            &request.organization_id,
            &request.policy_id,
        ) || !valid_text(&request.name, 240)
        {
            return Err(PluginError::domain(sla::CreatePolicyError::InvalidRequest));
        }
        let hash = request_hash(&request)?;
        let prepared = self.prepared().map_err(PluginError::runtime)?;
        let command = policy_command(
            &auth,
            sla::CREATE_POLICY_OPERATION,
            &request.idempotency_key,
            &hash,
        );
        let record = map_storage(
            storage::create_policy(
                &prepared.postgres,
                &command,
                &storage::PolicyCreate {
                    organization_id: &request.organization_id,
                    policy_id: &request.policy_id,
                    name: &request.name,
                    targets: &targets,
                },
            )
            .await,
            |failure| mutation_failure!(failure, CreatePolicyError),
        )?;
        wire_cast(&record)
    }

    async fn get_policy(
        &self,
        context: Ctx,
        request: sla::GetPolicyRequest,
    ) -> PluginResult<sla::GetPolicyResponse, sla::GetPolicyError> {
        management_auth!(
            self.authorize_management(
                &context,
                sla::GET_POLICY_OPERATION,
                &request.organization_id,
                "support.sla.read",
            )
            .await,
            GetPolicyError
        );
        if !valid_identifier(&request.organization_id, 512)
            || !valid_identifier(&request.policy_id, 512)
        {
            return Err(PluginError::domain(sla::GetPolicyError::InvalidRequest));
        }
        let prepared = self.prepared().map_err(PluginError::runtime)?;
        let record = map_storage(
            storage::get_policy(
                &prepared.postgres,
                &request.organization_id,
                &request.policy_id,
            )
            .await,
            |failure| read_failure!(failure, GetPolicyError),
        )?;
        wire_cast(&record)
    }

    async fn list_policies(
        &self,
        context: Ctx,
        request: sla::ListPoliciesRequest,
    ) -> PluginResult<sla::ListPoliciesResponse, sla::ListPoliciesError> {
        management_auth!(
            self.authorize_management(
                &context,
                sla::LIST_POLICIES_OPERATION,
                &request.organization_id,
                "support.sla.read",
            )
            .await,
            ListPoliciesError
        );
        if !valid_identifier(&request.organization_id, 512)
            || !(1..=200).contains(&request.limit)
            || request
                .after_policy_id
                .as_deref()
                .is_some_and(|value| !valid_identifier(value, 512))
        {
            return Err(PluginError::domain(sla::ListPoliciesError::InvalidRequest));
        }
        let prepared = self.prepared().map_err(PluginError::runtime)?;
        let record = map_storage(
            storage::list_policies(
                &prepared.postgres,
                &request.organization_id,
                request.include_archived,
                request.after_policy_id.as_deref(),
                request.limit,
            )
            .await,
            |failure| read_failure!(failure, ListPoliciesError),
        )?;
        wire_cast(&record)
    }

    async fn update_policy(
        &self,
        context: Ctx,
        request: sla::UpdatePolicyRequest,
    ) -> PluginResult<sla::UpdatePolicyResponse, sla::UpdatePolicyError> {
        let auth = management_auth!(
            self.authorize_management(
                &context,
                sla::UPDATE_POLICY_OPERATION,
                &request.organization_id,
                "support.sla.manage",
            )
            .await,
            UpdatePolicyError
        );
        let revision = parse_revision(&request.expected_revision)
            .ok_or_else(|| PluginError::domain(sla::UpdatePolicyError::InvalidRequest))?;
        let targets = request.targets.as_ref().map(|value| parse_targets(value));
        if !valid_command_fields(
            &request.idempotency_key,
            &request.organization_id,
            &request.policy_id,
        ) || (request.name.is_none() && request.targets.is_none())
            || request
                .name
                .as_deref()
                .is_some_and(|value| !valid_text(value, 240))
            || targets.as_ref().is_some_and(Option::is_none)
        {
            return Err(PluginError::domain(sla::UpdatePolicyError::InvalidRequest));
        }
        let targets = targets.flatten();
        let hash = request_hash(&request)?;
        let prepared = self.prepared().map_err(PluginError::runtime)?;
        let command = policy_command(
            &auth,
            sla::UPDATE_POLICY_OPERATION,
            &request.idempotency_key,
            &hash,
        );
        let record = map_storage(
            storage::update_policy(
                &prepared.postgres,
                &command,
                &storage::PolicyPatch {
                    organization_id: &request.organization_id,
                    policy_id: &request.policy_id,
                    expected_revision: revision,
                    name: request.name.as_deref(),
                    targets: targets.as_deref(),
                },
            )
            .await,
            |failure| mutation_failure!(failure, UpdatePolicyError),
        )?;
        wire_cast(&record)
    }

    async fn archive_policy(
        &self,
        context: Ctx,
        request: sla::ArchivePolicyRequest,
    ) -> PluginResult<sla::ArchivePolicyResponse, sla::ArchivePolicyError> {
        let auth = management_auth!(
            self.authorize_management(
                &context,
                sla::ARCHIVE_POLICY_OPERATION,
                &request.organization_id,
                "support.sla.manage",
            )
            .await,
            ArchivePolicyError
        );
        let revision = parse_revision(&request.expected_revision)
            .ok_or_else(|| PluginError::domain(sla::ArchivePolicyError::InvalidRequest))?;
        if !valid_command_fields(
            &request.idempotency_key,
            &request.organization_id,
            &request.policy_id,
        ) {
            return Err(PluginError::domain(sla::ArchivePolicyError::InvalidRequest));
        }
        let hash = request_hash(&request)?;
        let prepared = self.prepared().map_err(PluginError::runtime)?;
        let command = policy_command(
            &auth,
            sla::ARCHIVE_POLICY_OPERATION,
            &request.idempotency_key,
            &hash,
        );
        let record = map_storage(
            storage::archive_policy(
                &prepared.postgres,
                &command,
                &request.organization_id,
                &request.policy_id,
                revision,
            )
            .await,
            |failure| mutation_failure!(failure, ArchivePolicyError),
        )?;
        wire_cast(&record)
    }
}

impl SupportSlaPlugin {
    async fn observe_case_snapshot(
        &self,
        context: Ctx,
        request: sla::ObserveCaseSnapshotRequest,
    ) -> PluginResult<sla::ObserveCaseSnapshotResponse, sla::ObserveCaseSnapshotError> {
        let Some(caller) = self.observer_caller(&context) else {
            return Err(PluginError::domain(
                sla::ObserveCaseSnapshotError::Forbidden,
            ));
        };
        let created_at = parse_timestamp(&request.created_at)
            .ok_or_else(|| PluginError::domain(sla::ObserveCaseSnapshotError::InvalidRequest))?;
        let updated_at = parse_timestamp(&request.updated_at)
            .ok_or_else(|| PluginError::domain(sla::ObserveCaseSnapshotError::InvalidRequest))?;
        let resolved_at = parse_optional_timestamp(request.resolved_at.as_ref())
            .map_err(|()| PluginError::domain(sla::ObserveCaseSnapshotError::InvalidRequest))?;
        let closed_at = parse_optional_timestamp(request.closed_at.as_ref())
            .map_err(|()| PluginError::domain(sla::ObserveCaseSnapshotError::InvalidRequest))?;
        let priority = enum_string_plain(&request.priority)
            .ok_or_else(|| PluginError::domain(sla::ObserveCaseSnapshotError::InvalidRequest))?;
        let state = enum_string_plain(&request.state)
            .ok_or_else(|| PluginError::domain(sla::ObserveCaseSnapshotError::InvalidRequest))?;
        if !valid_observation_fields(
            &request.observation_id,
            &request.organization_id,
            &request.case_id,
            &request.source_case_revision,
        ) || !valid_identifier(&request.policy_id, 512)
            || created_at > updated_at
            || resolved_at.is_some_and(|value| value < created_at || value > updated_at)
            || closed_at.is_some_and(|value| value < created_at || value > updated_at)
            || (state == "resolved" && resolved_at.is_none())
            || (state == "closed" && closed_at.is_none())
            || (!matches!(state.as_str(), "resolved" | "closed")
                && (resolved_at.is_some() || closed_at.is_some()))
        {
            return Err(PluginError::domain(
                sla::ObserveCaseSnapshotError::InvalidRequest,
            ));
        }
        let hash = observation_hash(&request)?;
        let prepared = self.prepared().map_err(PluginError::runtime)?;
        let mut record = map_storage(
            storage::observe_case_snapshot(
                &prepared.postgres,
                &caller,
                &hash,
                &storage::CaseSnapshot {
                    observation_id: &request.observation_id,
                    organization_id: &request.organization_id,
                    case_id: &request.case_id,
                    source_case_revision: &request.source_case_revision,
                    policy_id: &request.policy_id,
                    priority: &priority,
                    state: &state,
                    created_at,
                    updated_at,
                    resolved_at,
                    closed_at,
                },
                self.config.reconciliation_interval_seconds,
            )
            .await,
            map_observation_failure,
        )?;
        record.successor_status = self
            .dispatch_schedule(&context, &prepared.postgres, record.schedule.as_ref())
            .await
            .map_err(PluginError::runtime)?
            .to_owned();
        wire_cast(&record)
    }

    async fn observe_case_message(
        &self,
        context: Ctx,
        request: sla::ObserveCaseMessageRequest,
    ) -> PluginResult<sla::ObserveCaseMessageResponse, sla::ObserveCaseMessageError> {
        let Some(caller) = self.observer_caller(&context) else {
            return Err(PluginError::domain(sla::ObserveCaseMessageError::Forbidden));
        };
        let occurred_at = parse_timestamp(&request.occurred_at)
            .ok_or_else(|| PluginError::domain(sla::ObserveCaseMessageError::InvalidRequest))?;
        let visibility = enum_string_plain(&request.visibility)
            .ok_or_else(|| PluginError::domain(sla::ObserveCaseMessageError::InvalidRequest))?;
        let author_kind = enum_string_plain(&request.author_kind)
            .ok_or_else(|| PluginError::domain(sla::ObserveCaseMessageError::InvalidRequest))?;
        if !valid_observation_fields(
            &request.observation_id,
            &request.organization_id,
            &request.case_id,
            &request.source_case_revision,
        ) || !valid_identifier(&request.message_id, 512)
        {
            return Err(PluginError::domain(
                sla::ObserveCaseMessageError::InvalidRequest,
            ));
        }
        let hash = observation_hash(&request)?;
        let prepared = self.prepared().map_err(PluginError::runtime)?;
        let mut record = map_storage(
            storage::observe_case_message(
                &prepared.postgres,
                &caller,
                &hash,
                &storage::CaseMessage {
                    observation_id: &request.observation_id,
                    organization_id: &request.organization_id,
                    case_id: &request.case_id,
                    message_id: &request.message_id,
                    source_case_revision: &request.source_case_revision,
                    visibility: &visibility,
                    author_kind: &author_kind,
                    occurred_at,
                },
                self.config.reconciliation_interval_seconds,
            )
            .await,
            map_message_observation_failure,
        )?;
        record.successor_status = self
            .dispatch_schedule(&context, &prepared.postgres, record.schedule.as_ref())
            .await
            .map_err(PluginError::runtime)?
            .to_owned();
        wire_cast(&record)
    }

    async fn reconcile(
        &self,
        context: Ctx,
        request: sla::ReconcileRequest,
    ) -> PluginResult<sla::ReconcileResponse, sla::ReconcileError> {
        let Some(caller) = self.worker_caller(&context) else {
            return Err(PluginError::domain(sla::ReconcileError::Forbidden));
        };
        let observed_at = parse_timestamp(&request.observed_at)
            .ok_or_else(|| PluginError::domain(sla::ReconcileError::InvalidRequest))?;
        if !valid_identifier(&request.run_id, 200)
            || !(1..=self.config.max_reconcile_batch).contains(&request.limit)
        {
            return Err(PluginError::domain(sla::ReconcileError::InvalidRequest));
        }
        let hash = request_hash(&request)?;
        let prepared = self.prepared().map_err(PluginError::runtime)?;
        let fallback_schedule = storage::arrange_reconcile_successor(
            &prepared.postgres,
            &request.run_id,
            observed_at,
            self.config.reconciliation_interval_seconds,
        )
        .await
        .map_err(storage_runtime)
        .map_err(PluginError::runtime)?;
        let result = storage::reconcile(
            &prepared.postgres,
            &caller,
            &request.run_id,
            &hash,
            observed_at,
            request.limit,
            self.config.reconciliation_interval_seconds,
        )
        .await;
        let mut record = match result {
            Ok(record) => record,
            Err(error) => {
                self.dispatch_schedule(&context, &prepared.postgres, Some(&fallback_schedule))
                    .await
                    .map_err(PluginError::runtime)?;
                return match error {
                    StorageError::Domain(DomainFailure::RunConflict) => {
                        Err(PluginError::domain(sla::ReconcileError::RunConflict))
                    }
                    StorageError::Domain(_) => {
                        Err(PluginError::domain(sla::ReconcileError::InvalidRequest))
                    }
                    error => Err(PluginError::runtime(storage_runtime(error))),
                };
            }
        };
        record.successor_status = self
            .dispatch_schedule(&context, &prepared.postgres, record.schedule.as_ref())
            .await
            .map_err(PluginError::runtime)?
            .to_owned();
        wire_cast(&record)
    }

    async fn get_clock(
        &self,
        context: Ctx,
        request: sla::GetClockRequest,
    ) -> PluginResult<sla::GetClockResponse, sla::GetClockError> {
        management_auth!(
            self.authorize_management(
                &context,
                sla::GET_CLOCK_OPERATION,
                &request.organization_id,
                "support.sla.read",
            )
            .await,
            GetClockError
        );
        let kind = enum_string_plain(&request.kind)
            .ok_or_else(|| PluginError::domain(sla::GetClockError::InvalidRequest))?;
        if !valid_identifier(&request.organization_id, 512)
            || !valid_identifier(&request.case_id, 512)
        {
            return Err(PluginError::domain(sla::GetClockError::InvalidRequest));
        }
        let prepared = self.prepared().map_err(PluginError::runtime)?;
        let record = map_storage(
            storage::get_clock(
                &prepared.postgres,
                &request.organization_id,
                &request.case_id,
                &kind,
            )
            .await,
            |failure| read_failure!(failure, GetClockError),
        )?;
        wire_cast(&record)
    }

    async fn list_clocks(
        &self,
        context: Ctx,
        request: sla::ListClocksRequest,
    ) -> PluginResult<sla::ListClocksResponse, sla::ListClocksError> {
        management_auth!(
            self.authorize_management(
                &context,
                sla::LIST_CLOCKS_OPERATION,
                &request.organization_id,
                "support.sla.read",
            )
            .await,
            ListClocksError
        );
        if !valid_list_request(
            &request.organization_id,
            request.case_id.as_deref(),
            request.after_clock_id.as_deref(),
            request.limit,
        ) || request
            .status
            .as_deref()
            .is_some_and(|value| !matches!(value, "running" | "met" | "breached" | "canceled"))
        {
            return Err(PluginError::domain(sla::ListClocksError::InvalidRequest));
        }
        let prepared = self.prepared().map_err(PluginError::runtime)?;
        let record = map_storage(
            storage::list_clocks(
                &prepared.postgres,
                &request.organization_id,
                request.case_id.as_deref(),
                request.status.as_deref(),
                request.after_clock_id.as_deref(),
                request.limit,
            )
            .await,
            |failure| read_failure!(failure, ListClocksError),
        )?;
        wire_cast(&record)
    }

    async fn list_breaches(
        &self,
        context: Ctx,
        request: sla::ListBreachesRequest,
    ) -> PluginResult<sla::ListBreachesResponse, sla::ListBreachesError> {
        management_auth!(
            self.authorize_management(
                &context,
                sla::LIST_BREACHES_OPERATION,
                &request.organization_id,
                "support.sla.read",
            )
            .await,
            ListBreachesError
        );
        if !valid_list_request(
            &request.organization_id,
            request.case_id.as_deref(),
            request.after_breach_id.as_deref(),
            request.limit,
        ) || request
            .notification_status
            .as_deref()
            .is_some_and(|value| !matches!(value, "pending_adapter" | "delivered" | "failed"))
        {
            return Err(PluginError::domain(sla::ListBreachesError::InvalidRequest));
        }
        let prepared = self.prepared().map_err(PluginError::runtime)?;
        let record = map_storage(
            storage::list_breaches(
                &prepared.postgres,
                &request.organization_id,
                request.case_id.as_deref(),
                request.notification_status.as_deref(),
                request.after_breach_id.as_deref(),
                request.limit,
            )
            .await,
            |failure| read_failure!(failure, ListBreachesError),
        )?;
        wire_cast(&record)
    }
}

impl SupportSlaPlugin {
    async fn dispatch_schedule(
        &self,
        context: &Ctx,
        postgres: &OwnedPostgres,
        schedule: Option<&storage::ScheduleRecord>,
    ) -> Result<&'static str, RuntimeFailure> {
        let Some(schedule) = schedule else {
            return Ok("not_required");
        };
        if schedule.status == "enqueued" {
            return Ok("enqueued");
        }
        if schedule.status == "consumed" {
            return Ok("not_required");
        }
        let Some(provider) = self.jobs.first() else {
            return Ok("pending_external_worker");
        };
        let request = serde_json::from_value::<jobs::EnqueueRequest>(serde_json::json!({
            "available_at": schedule.available_at,
            "idempotency_key": schedule.idempotency_key,
            "kind": "support_sla.reconcile",
            "max_attempts": 10,
            "payload": {
                "capability_id": sla::CAPABILITY_ID,
                "operation": sla::RECONCILE_OPERATION,
                "schedule_id": schedule.schedule_id,
                "worker_contract": "configured-exact-caller"
            },
            "queue": self.config.jobs_queue
        }))
        .map_err(|error| RuntimeFailure::Internal {
            detail: format!("Support SLA Jobs request encoding failed: {error}"),
        })?;
        match provider
            .enqueue_with_context(context.clone(), request)
            .await
        {
            Ok(response) => {
                storage::mark_schedule_enqueued(postgres, &schedule.schedule_id, &response.job_id)
                    .await
                    .map_err(storage_runtime)?;
                Ok("enqueued")
            }
            Err(jobs::JobsEnqueueInvocationError::Runtime(error)) => {
                storage::mark_schedule_failed(postgres, &schedule.schedule_id, "jobs_runtime")
                    .await
                    .map_err(storage_runtime)?;
                Err(error)
            }
            Err(jobs::JobsEnqueueInvocationError::Domain(_)) => {
                storage::mark_schedule_failed(postgres, &schedule.schedule_id, "jobs_domain")
                    .await
                    .map_err(storage_runtime)?;
                Err(RuntimeFailure::PluginFailure {
                    detail: "Jobs rejected the Support SLA successor schedule".to_owned(),
                })
            }
        }
    }
}

impl Lifecycle for SupportSlaPlugin {
    async fn activate(&self, context: ActivateContext) -> Result<(), RuntimeFailure> {
        if self.jobs.len() > 1 {
            return Err(RuntimeFailure::InvalidResolvedPlan {
                detail: "Support SLA accepts zero or one Jobs provider".to_owned(),
            });
        }
        let database_url = resolve_secret(
            &self.secrets,
            context.dependencies(),
            context.cancellation(),
            &self.config.database_url_secret,
        )
        .await?;
        let postgres = OwnedPostgres::prepare(
            &database_url,
            schema::schema_plan(self.config.schema.clone()).map_err(|error| {
                RuntimeFailure::InvalidResolvedPlan {
                    detail: error.to_string(),
                }
            })?,
        )
        .await
        .map_err(|error| RuntimeFailure::PluginFailure {
            detail: error.to_string(),
        })?;
        self.prepared
            .borrow_mut()
            .replace(PreparedSupportSla { postgres });
        Ok(())
    }

    async fn deactivate(&self, _context: DeactivateContext) -> Result<(), RuntimeFailure> {
        let prepared = self.prepared.borrow_mut().take();
        if let Some(prepared) = prepared {
            prepared.postgres.pool().close().await;
        }
        Ok(())
    }
}

fn map_storage<T, E>(
    result: Result<T, StorageError>,
    map: impl FnOnce(DomainFailure) -> E,
) -> PluginResult<T, E> {
    match result {
        Ok(value) => Ok(value),
        Err(StorageError::Domain(error)) => Err(PluginError::domain(map(error))),
        Err(error) => Err(PluginError::runtime(storage_runtime(error))),
    }
}

fn map_observation_failure(failure: DomainFailure) -> sla::ObserveCaseSnapshotError {
    match failure {
        DomainFailure::PolicyNotFound => sla::ObserveCaseSnapshotError::PolicyNotFound,
        DomainFailure::PolicyArchived => sla::ObserveCaseSnapshotError::PolicyArchived,
        DomainFailure::CaseNotObserved => sla::ObserveCaseSnapshotError::CaseNotObserved,
        DomainFailure::StaleObservation => sla::ObserveCaseSnapshotError::StaleObservation,
        DomainFailure::ObservationConflict => sla::ObserveCaseSnapshotError::ObservationConflict,
        _ => sla::ObserveCaseSnapshotError::InvalidRequest,
    }
}

fn map_message_observation_failure(failure: DomainFailure) -> sla::ObserveCaseMessageError {
    match failure {
        DomainFailure::PolicyNotFound => sla::ObserveCaseMessageError::PolicyNotFound,
        DomainFailure::PolicyArchived => sla::ObserveCaseMessageError::PolicyArchived,
        DomainFailure::CaseNotObserved => sla::ObserveCaseMessageError::CaseNotObserved,
        DomainFailure::StaleObservation => sla::ObserveCaseMessageError::StaleObservation,
        DomainFailure::ObservationConflict => sla::ObserveCaseMessageError::ObservationConflict,
        _ => sla::ObserveCaseMessageError::InvalidRequest,
    }
}

#[allow(clippy::needless_pass_by_value)]
fn storage_runtime(error: StorageError) -> RuntimeFailure {
    RuntimeFailure::PluginFailure {
        detail: error.to_string(),
    }
}

fn policy_command<'a>(
    auth: &'a Authorized,
    operation: &'a str,
    key: &'a str,
    hash: &'a [u8],
) -> storage::Command<'a> {
    storage::Command {
        caller: &auth.caller,
        actor: &auth.actor,
        operation,
        key,
        hash,
    }
}

async fn resolve_secret(
    secrets: &secrets::SecretsClient,
    dependencies: &PluginDependencies,
    cancellation: lenso_kernel::CancellationToken,
    reference: &str,
) -> Result<Zeroizing<String>, RuntimeFailure> {
    let context = dependencies.invocation_context_after(DEPENDENCY_TIMEOUT, cancellation)?;
    secrets
        .resolve_with_context(
            context,
            ResolveRequest {
                reference: reference.to_owned(),
            },
        )
        .await
        .map(|value| Zeroizing::new(value.value))
        .map_err(|error| match error {
            SecretsInvocationError::Domain(_) => RuntimeFailure::PluginFailure {
                detail: "Support SLA database secret was rejected".to_owned(),
            },
            SecretsInvocationError::Runtime(error) => error,
        })
}

fn request_hash<T: Serialize, E>(request: &T) -> Result<Vec<u8>, PluginError<E>> {
    serde_json::to_vec(request)
        .map(|wire| Sha256::digest(wire).to_vec())
        .map_err(serialization_runtime)
}

fn observation_hash<T: Serialize, E>(request: &T) -> Result<Vec<u8>, PluginError<E>> {
    let mut value = serde_json::to_value(request).map_err(serialization_runtime)?;
    let object = value.as_object_mut().ok_or_else(|| {
        PluginError::runtime(RuntimeFailure::Internal {
            detail: "Support SLA observation projection is not an object".to_owned(),
        })
    })?;
    object.remove("observation_id");
    serde_json::to_vec(&value)
        .map(|wire| Sha256::digest(wire).to_vec())
        .map_err(serialization_runtime)
}

fn wire_cast<T: Serialize, U: DeserializeOwned, E>(value: &T) -> Result<U, PluginError<E>> {
    serde_json::to_value(value)
        .and_then(serde_json::from_value)
        .map_err(serialization_runtime)
}

#[allow(clippy::needless_pass_by_value)]
fn serialization_runtime<E>(error: serde_json::Error) -> PluginError<E> {
    PluginError::runtime(RuntimeFailure::Internal {
        detail: format!("Support SLA wire projection failed: {error}"),
    })
}

fn parse_targets(values: &[sla::Target]) -> Option<Vec<storage::TargetRecord>> {
    if values.len() != 4 {
        return None;
    }
    let mut priorities = BTreeSet::new();
    let mut targets = Vec::with_capacity(values.len());
    for value in values {
        let priority = enum_string_plain(&value.priority)?;
        if !priorities.insert(priority.clone())
            || !(60..=31_536_000).contains(&value.first_response_seconds)
            || !(60..=31_536_000).contains(&value.resolution_seconds)
            || value.resolution_seconds < value.first_response_seconds
        {
            return None;
        }
        targets.push(storage::TargetRecord {
            priority,
            first_response_seconds: value.first_response_seconds,
            resolution_seconds: value.resolution_seconds,
        });
    }
    (priorities
        == BTreeSet::from([
            "high".to_owned(),
            "low".to_owned(),
            "normal".to_owned(),
            "urgent".to_owned(),
        ]))
    .then_some(targets)
}

fn enum_string_plain(value: &impl Serialize) -> Option<String> {
    serde_json::to_value(value)
        .ok()?
        .as_str()
        .map(ToOwned::to_owned)
}

fn parse_timestamp(value: &impl Serialize) -> Option<OffsetDateTime> {
    serde_json::to_value(value)
        .ok()?
        .as_str()
        .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())
}

fn parse_optional_timestamp(value: Option<&impl Serialize>) -> Result<Option<OffsetDateTime>, ()> {
    match value {
        Some(value) => parse_timestamp(value).map(Some).ok_or(()),
        None => Ok(None),
    }
}

fn parse_revision(value: &str) -> Option<i64> {
    value.parse().ok().filter(|revision| *revision > 0)
}

fn valid_command_fields(key: &str, organization_id: &str, policy_id: &str) -> bool {
    valid_identifier(key, 200)
        && valid_identifier(organization_id, 512)
        && valid_identifier(policy_id, 512)
}

fn valid_observation_fields(
    observation_id: &str,
    organization_id: &str,
    case_id: &str,
    source_revision: &str,
) -> bool {
    valid_identifier(observation_id, 200)
        && valid_identifier(organization_id, 512)
        && valid_identifier(case_id, 512)
        && valid_identifier(source_revision, 128)
}

fn valid_list_request(
    organization_id: &str,
    case_id: Option<&str>,
    after: Option<&str>,
    limit: i64,
) -> bool {
    valid_identifier(organization_id, 512)
        && case_id.is_none_or(|value| valid_identifier(value, 512))
        && after.is_none_or(|value| valid_identifier(value, 512))
        && (1..=200).contains(&limit)
}

fn valid_callers(values: &[String]) -> bool {
    !values.is_empty()
        && values.len() <= MAX_CALLERS
        && values.iter().all(|value| valid_identifier(value, 256))
        && values.iter().collect::<BTreeSet<_>>().len() == values.len()
}

fn valid_secret_reference(value: &str) -> bool {
    valid_identifier(value, 512) && !value.starts_with('/')
}

fn valid_jobs_name(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' | b'/')
        })
}

fn valid_identifier(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn valid_text(value: &str, max: usize) -> bool {
    !value.trim().is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}

fn exact_caller(context: &Ctx, allowed: &[String]) -> Option<String> {
    context
        .caller_instance()
        .filter(|caller| allowed.iter().any(|allowed| allowed == *caller))
        .map(ToOwned::to_owned)
}

#[derive(Clone, Debug)]
struct SupportSlaActor {
    subject: String,
}

impl TypedActor for SupportSlaActor {
    fn from_assertion(assertion: &ActorAssertion) -> Result<Self, ActorProjectionError> {
        Ok(Self {
            subject: assertion.subject().to_owned(),
        })
    }
}

#[derive(Clone, Copy, Debug)]
struct UtcClock;

impl AssertionClock for UtcClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lenso_app_plan::{
        AppComposition, CapabilityBinding, CapabilityEndpointPlan, CapabilityRequirementPlan,
        PluginInstancePlan,
    };
    use lenso_auth_sdk::{ActorAssertionIssuer, Validity, audience};
    use lenso_capability_access_control::{
        AccessControl, AccessControlEndpoint, AccessControlProvider, CheckPermissionError,
        CheckPermissionResponse,
    };
    use lenso_capability_organization_membership::{
        CheckMembershipError, CheckMembershipResponse, OrganizationMembership,
        OrganizationMembershipEndpoint, OrganizationMembershipProvider,
    };
    use lenso_capability_secrets::{
        ResolveError, ResolveResponse, Secrets, SecretsEndpoint, SecretsProvider,
    };
    use lenso_kernel::{
        CancellationToken, InvocationContext, Kernel, NativeRequestEndpoint, NativeRequestFuture,
    };
    use lenso_native_adapter::{
        NativePluginFactory, NativePluginFactoryContext, NativePluginInstance, NativePluginRegistry,
    };
    use lenso_runner::TokioDriver;
    use time::Duration as TimeDuration;

    const FAKE_PREREQUISITES_PACKAGE: &str = "test.support-sla-prerequisites";

    fn config() -> SupportSlaConfig {
        let issuer = ActorAssertionIssuer::new("auth.users", b"support-sla-test-key");
        SupportSlaConfig::new(
            "support_sla",
            "support-sla/database-url",
            "auth.users",
            issuer.public_key_base64(),
            vec!["support-sla-admin".to_owned()],
            vec!["support-case-observer".to_owned()],
            vec!["support-sla-worker".to_owned()],
            "support-sla".to_owned(),
            300,
            100,
        )
        .unwrap()
    }

    fn context(caller: &str) -> InvocationContext {
        InvocationContext::new(1, None, CancellationToken::new()).with_caller_instance(caller)
    }

    #[test]
    fn descriptor_is_linked_and_declares_exact_dependencies() {
        let descriptor: serde_json::Value = serde_json::from_str(PLUGIN_DESCRIPTOR_JSON).unwrap();
        assert_eq!(
            descriptor["provided_capabilities"][0]["capability_id"],
            sla::CAPABILITY_ID
        );
        let required = descriptor["required_capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| {
                (
                    value["capability_id"].as_str().unwrap(),
                    value["cardinality"].as_str().unwrap(),
                )
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(
            required,
            BTreeSet::from([
                (access::CAPABILITY_ID, "one"),
                (jobs::CAPABILITY_ID, "many"),
                (membership::CAPABILITY_ID, "one"),
                (secrets::CAPABILITY_ID, "one"),
            ])
        );
        assert_eq!(sla::DESCRIPTOR_VERSION, "1.0.0");
        assert_eq!(
            NativePluginRegistry::new()
                .with_linked_factories()
                .factories()
                .filter(|factory| factory.package_id() == PACKAGE_ID)
                .count(),
            1
        );
    }

    #[test]
    fn config_rejects_role_overlap_and_ambient_callers() {
        let mut invalid = config();
        invalid.worker_callers = invalid.observer_callers.clone();
        assert_eq!(
            invalid.validate(),
            Err(SupportSlaConfigError::OverlappingCallers)
        );
        let mut invalid = config();
        invalid.management_callers = vec![String::new()];
        assert_eq!(
            invalid.validate(),
            Err(SupportSlaConfigError::InvalidManagementCallers)
        );
    }

    #[test]
    fn assertions_and_callers_are_bound_to_exact_operations_and_instances() {
        let issuer = ActorAssertionIssuer::new("auth.users", b"support-sla-test-key");
        let now = OffsetDateTime::now_utc();
        let assertion = issuer.issue(
            "usr_sla_admin",
            "user",
            "strong",
            [audience(sla::CAPABILITY_ID, sla::CREATE_POLICY_OPERATION)],
            Validity::new(
                now - TimeDuration::seconds(1),
                now + TimeDuration::minutes(1),
            )
            .unwrap(),
            std::collections::BTreeMap::new(),
        );
        let create = assertion
            .attach(context("support-sla-admin"))
            .expect("assertion attaches");
        let verifier = config().verifier().unwrap();
        assert!(
            verifier
                .project_context::<SupportSlaActor>(
                    &create,
                    sla::CAPABILITY_ID,
                    sla::CREATE_POLICY_OPERATION,
                    &UtcClock,
                )
                .is_ok()
        );
        assert!(
            verifier
                .project_context::<SupportSlaActor>(
                    &create,
                    sla::CAPABILITY_ID,
                    sla::UPDATE_POLICY_OPERATION,
                    &UtcClock,
                )
                .is_err()
        );
        assert_eq!(
            exact_caller(
                &context("support-case-observer"),
                &config().observer_callers
            ),
            Some("support-case-observer".to_owned())
        );
        assert_eq!(
            exact_caller(
                &context("support-case-observer-shadow"),
                &config().observer_callers
            ),
            None
        );
    }

    #[test]
    fn policy_targets_cover_every_priority_and_preserve_24x7_constraint() {
        let targets: Vec<sla::Target> = serde_json::from_value(serde_json::json!([
            {"priority":"low","first_response_seconds":3600,"resolution_seconds":86400},
            {"priority":"normal","first_response_seconds":1800,"resolution_seconds":43200},
            {"priority":"high","first_response_seconds":900,"resolution_seconds":14400},
            {"priority":"urgent","first_response_seconds":300,"resolution_seconds":3600}
        ]))
        .unwrap();
        assert!(parse_targets(&targets).is_some());
        let mut duplicated = targets;
        duplicated[3].priority = sla::TargetPriority::High;
        assert!(parse_targets(&duplicated).is_none());
        assert!(
            include_str!("../migrations/001_create_support_sla.sql")
                .contains("business_calendar = 'utc_24x7'")
        );
    }

    #[test]
    fn fact_hash_deduplicates_new_observation_ids_but_not_changed_facts() {
        let mut request: sla::ObserveCaseMessageRequest =
            serde_json::from_value(serde_json::json!({
                "observation_id": "observation-1",
                "organization_id": "org_1",
                "case_id": "case_1",
                "message_id": "message_1",
                "source_case_revision": "7",
                "visibility": "public",
                "author_kind": "agent",
                "occurred_at": "2026-08-31T00:00:00Z"
            }))
            .unwrap();
        let original = observation_hash::<_, sla::ObserveCaseMessageError>(&request).unwrap();
        request.observation_id = "observation-2".to_owned();
        assert_eq!(
            original,
            observation_hash::<_, sla::ObserveCaseMessageError>(&request).unwrap()
        );
        request.message_id = "message-2".to_owned();
        assert_ne!(
            original,
            observation_hash::<_, sla::ObserveCaseMessageError>(&request).unwrap()
        );
    }

    #[test]
    fn removing_sla_leaves_support_case_capability_resolvable() {
        let support_case = PluginInstancePlan::new("support-case", "lenso.support-case.postgres")
            .with_capability(CapabilityEndpointPlan::new(
                "lenso.support-case@1",
                "1.0.0",
                [
                    "add_message",
                    "assign_case",
                    "create_case",
                    "get_case",
                    "list_cases",
                    "list_messages",
                    "transition_case",
                    "update_case",
                ],
            ));
        let remaining = AppComposition::new(vec![support_case], Vec::new())
            .resolve()
            .expect("Support Case has no dependency on the removable SLA Plugin");
        assert_eq!(remaining.plugin_instances().len(), 1);
        assert_eq!(
            remaining.plugin_instances()[0].provided_capabilities()[0].capability_id(),
            "lenso.support-case@1"
        );
        assert!(remaining.capability_bindings().is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn kernel_with_fake_prerequisites_rejects_invalid_config_before_database_access() {
        let mut invalid = config();
        invalid.worker_callers = invalid.observer_callers.clone();
        let plan = support_sla_plan(&serde_json::to_string(&invalid).unwrap());
        let local = tokio::task::LocalSet::new();
        let error = local
            .run_until(async {
                Kernel::start_native(
                    plan,
                    TokioDriver::new(),
                    NativePluginRegistry::new()
                        .with_linked_factories()
                        .with_factory(FakePrerequisitesFactory),
                )
                .await
                .unwrap_err()
            })
            .await;
        assert!(matches!(error, RuntimeFailure::InvalidResolvedPlan { .. }));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn kernel_connects_fake_prerequisites_and_zero_jobs_before_pg_prepare() {
        let plan = support_sla_plan(&serde_json::to_string(&config()).unwrap());
        let local = tokio::task::LocalSet::new();
        let error = local
            .run_until(async {
                Kernel::start_native(
                    plan,
                    TokioDriver::new(),
                    NativePluginRegistry::new()
                        .with_linked_factories()
                        .with_factory(FakePrerequisitesFactory),
                )
                .await
                .unwrap_err()
            })
            .await;
        assert!(matches!(error, RuntimeFailure::PluginFailure { .. }));
    }

    #[derive(Clone, Copy, Debug)]
    struct FakePrerequisites;

    impl SecretsProvider for FakePrerequisites {
        fn resolve(
            &self,
            _context: InvocationContext,
            _request: ResolveRequest,
        ) -> NativeRequestFuture<Secrets> {
            Box::pin(futures::future::ready(Ok(Ok(ResolveResponse {
                value: "not-a-postgres-url".to_owned(),
            }))))
        }
    }

    impl OrganizationMembershipProvider for FakePrerequisites {
        fn check_membership(
            &self,
            _context: InvocationContext,
            _request: CheckMembershipRequest,
        ) -> NativeRequestFuture<OrganizationMembership> {
            Box::pin(futures::future::ready(Ok(Ok(CheckMembershipResponse {
                active: true,
                owner: false,
            }))))
        }
    }

    impl AccessControlProvider for FakePrerequisites {
        fn check_permission(
            &self,
            _context: InvocationContext,
            _request: CheckPermissionRequest,
        ) -> NativeRequestFuture<AccessControl> {
            Box::pin(futures::future::ready(Ok(Ok(CheckPermissionResponse {
                allowed: true,
                policy_revision: "1".to_owned(),
            }))))
        }
    }

    #[derive(Clone, Copy, Debug)]
    struct FakePrerequisitesFactory;

    impl NativePluginFactory for FakePrerequisitesFactory {
        fn package_id(&self) -> &'static str {
            FAKE_PREREQUISITES_PACKAGE
        }

        fn instantiate(
            &self,
            _context: NativePluginFactoryContext<'_>,
        ) -> Result<NativePluginInstance, RuntimeFailure> {
            Ok(NativePluginInstance::new(vec![
                Rc::new(SecretsEndpoint::new(FakePrerequisites)) as Rc<dyn NativeRequestEndpoint>,
                Rc::new(OrganizationMembershipEndpoint::new(FakePrerequisites))
                    as Rc<dyn NativeRequestEndpoint>,
                Rc::new(AccessControlEndpoint::new(FakePrerequisites))
                    as Rc<dyn NativeRequestEndpoint>,
            ]))
        }
    }

    fn support_sla_plan(configuration: &str) -> lenso_app_plan::ResolvedAppPlan {
        let plugin = PluginInstancePlan::new("support-sla", PACKAGE_ID)
            .with_configuration(configuration)
            .with_capability(CapabilityEndpointPlan::new(
                sla::CAPABILITY_ID,
                sla::DESCRIPTOR_VERSION,
                [
                    sla::ARCHIVE_POLICY_OPERATION,
                    sla::CREATE_POLICY_OPERATION,
                    sla::GET_CLOCK_OPERATION,
                    sla::GET_POLICY_OPERATION,
                    sla::LIST_BREACHES_OPERATION,
                    sla::LIST_CLOCKS_OPERATION,
                    sla::LIST_POLICIES_OPERATION,
                    sla::OBSERVE_CASE_MESSAGE_OPERATION,
                    sla::OBSERVE_CASE_SNAPSHOT_OPERATION,
                    sla::RECONCILE_OPERATION,
                    sla::UPDATE_POLICY_OPERATION,
                ],
            ))
            .with_requirement(CapabilityRequirementPlan::one(
                secrets::CAPABILITY_ID,
                secrets::DESCRIPTOR_VERSION,
            ))
            .with_requirement(CapabilityRequirementPlan::one(
                membership::CAPABILITY_ID,
                membership::DESCRIPTOR_VERSION,
            ))
            .with_requirement(CapabilityRequirementPlan::one(
                access::CAPABILITY_ID,
                access::DESCRIPTOR_VERSION,
            ))
            .with_requirement(CapabilityRequirementPlan::many(
                jobs::CAPABILITY_ID,
                jobs::DESCRIPTOR_VERSION,
            ));
        let prerequisites = PluginInstancePlan::new("prerequisites", FAKE_PREREQUISITES_PACKAGE)
            .with_capability(CapabilityEndpointPlan::new(
                secrets::CAPABILITY_ID,
                secrets::DESCRIPTOR_VERSION,
                [secrets::RESOLVE_OPERATION],
            ))
            .with_capability(CapabilityEndpointPlan::new(
                membership::CAPABILITY_ID,
                membership::DESCRIPTOR_VERSION,
                [membership::CHECK_MEMBERSHIP_OPERATION],
            ))
            .with_capability(CapabilityEndpointPlan::new(
                access::CAPABILITY_ID,
                access::DESCRIPTOR_VERSION,
                [access::CHECK_PERMISSION_OPERATION],
            ));
        AppComposition::new(
            vec![plugin, prerequisites],
            vec![
                CapabilityBinding::new(
                    "support-sla",
                    secrets::CAPABILITY_ID,
                    secrets::DESCRIPTOR_VERSION,
                    "prerequisites",
                ),
                CapabilityBinding::new(
                    "support-sla",
                    membership::CAPABILITY_ID,
                    membership::DESCRIPTOR_VERSION,
                    "prerequisites",
                ),
                CapabilityBinding::new(
                    "support-sla",
                    access::CAPABILITY_ID,
                    access::DESCRIPTOR_VERSION,
                    "prerequisites",
                ),
            ],
        )
        .resolve()
        .unwrap()
    }

    #[allow(dead_code)]
    fn _provider_error_types_are_linked(
        _: ResolveError,
        _: CheckMembershipError,
        _: CheckPermissionError,
    ) {
    }
}
