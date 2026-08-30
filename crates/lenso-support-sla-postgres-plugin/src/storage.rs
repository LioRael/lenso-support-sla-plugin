use lenso_postgres_kit::OwnedPostgres;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row, Transaction};
use thiserror::Error;
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct TargetRecord {
    pub priority: String,
    pub first_response_seconds: i64,
    pub resolution_seconds: i64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct PolicyRecord {
    pub organization_id: String,
    pub policy_id: String,
    pub name: String,
    pub business_calendar: String,
    pub targets: Vec<TargetRecord>,
    pub archived: bool,
    pub revision: String,
    pub created_at: String,
    pub updated_at: String,
    pub archived_at: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct PolicyListRecord {
    pub policies: Vec<PolicyRecord>,
    pub next_after_policy_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct ClockRecord {
    pub clock_id: String,
    pub organization_id: String,
    pub case_id: String,
    pub policy_id: String,
    pub policy_revision: String,
    pub priority: String,
    pub kind: String,
    pub target_seconds: i64,
    pub started_at: String,
    pub target_at: String,
    pub status: String,
    pub satisfied_at: Option<String>,
    pub breached_at: Option<String>,
    pub next_fire_at: Option<String>,
    pub revision: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct ClockListRecord {
    pub clocks: Vec<ClockRecord>,
    pub next_after_clock_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct BreachRecord {
    pub breach_id: String,
    pub organization_id: String,
    pub case_id: String,
    pub clock_id: String,
    pub kind: String,
    pub target_at: String,
    pub breached_at: String,
    pub clock_revision: String,
    pub notification_outbox_id: String,
    pub notification_status: String,
    pub notification_attempts: i64,
    pub notification_last_error_code: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct BreachListRecord {
    pub breaches: Vec<BreachRecord>,
    pub next_after_breach_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct ScheduleRecord {
    pub schedule_id: String,
    pub idempotency_key: String,
    pub available_at: String,
    pub status: String,
    pub job_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct ObservationRecord {
    pub accepted: bool,
    pub replayed: bool,
    pub case_id: String,
    pub source_case_revision: String,
    pub clocks_changed: i64,
    pub next_fire_at: Option<String>,
    pub successor_schedule_id: Option<String>,
    pub successor_status: String,
    #[serde(skip)]
    pub schedule: Option<ScheduleRecord>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct ReconcileRecord {
    pub run_id: String,
    pub replayed: bool,
    pub processed_clocks: i64,
    pub new_breaches: i64,
    pub next_fire_at: Option<String>,
    pub successor_schedule_id: Option<String>,
    pub successor_status: String,
    #[serde(skip)]
    pub schedule: Option<ScheduleRecord>,
}

#[derive(Clone, Debug)]
pub(crate) struct Command<'a> {
    pub caller: &'a str,
    pub actor: &'a str,
    pub operation: &'a str,
    pub key: &'a str,
    pub hash: &'a [u8],
}

#[derive(Clone, Debug)]
pub(crate) struct PolicyCreate<'a> {
    pub organization_id: &'a str,
    pub policy_id: &'a str,
    pub name: &'a str,
    pub targets: &'a [TargetRecord],
}

#[derive(Clone, Debug)]
pub(crate) struct PolicyPatch<'a> {
    pub organization_id: &'a str,
    pub policy_id: &'a str,
    pub expected_revision: i64,
    pub name: Option<&'a str>,
    pub targets: Option<&'a [TargetRecord]>,
}

#[derive(Clone, Debug)]
pub(crate) struct CaseSnapshot<'a> {
    pub observation_id: &'a str,
    pub organization_id: &'a str,
    pub case_id: &'a str,
    pub source_case_revision: &'a str,
    pub policy_id: &'a str,
    pub priority: &'a str,
    pub state: &'a str,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub resolved_at: Option<OffsetDateTime>,
    pub closed_at: Option<OffsetDateTime>,
}

#[derive(Clone, Debug)]
pub(crate) struct CaseMessage<'a> {
    pub observation_id: &'a str,
    pub organization_id: &'a str,
    pub case_id: &'a str,
    pub message_id: &'a str,
    pub source_case_revision: &'a str,
    pub visibility: &'a str,
    pub author_kind: &'a str,
    pub occurred_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DomainFailure {
    NotFound,
    Archived,
    RevisionConflict,
    IdempotencyConflict,
    OperationInProgress,
    AlreadyExists,
    PolicyNotFound,
    PolicyArchived,
    CaseNotObserved,
    StaleObservation,
    ObservationConflict,
    RunConflict,
}

#[derive(Debug, Error)]
pub(crate) enum StorageError {
    #[error("domain failure: {0:?}")]
    Domain(DomainFailure),
    #[error("database failure during {operation}: {source}")]
    Database {
        operation: &'static str,
        #[source]
        source: sqlx::Error,
    },
    #[error("failed to encode or decode a durable receipt: {0}")]
    Receipt(#[from] serde_json::Error),
    #[error("failed to format a timestamp: {0}")]
    Time(#[from] time::error::Format),
}

impl From<DomainFailure> for StorageError {
    fn from(value: DomainFailure) -> Self {
        Self::Domain(value)
    }
}

pub(crate) async fn create_policy(
    postgres: &OwnedPostgres,
    command: &Command<'_>,
    value: &PolicyCreate<'_>,
) -> Result<PolicyRecord, StorageError> {
    let mut tx = begin(postgres, "begin create policy").await?;
    if let Some(replay) = admit_command(&mut tx, command).await? {
        commit(tx, "commit create policy replay").await?;
        return Ok(replay);
    }
    let inserted = sqlx::query(
        "INSERT INTO sla_policies(organization_id,policy_id,name,business_calendar) VALUES($1,$2,$3,'utc_24x7')",
    )
    .bind(value.organization_id)
    .bind(value.policy_id)
    .bind(value.name)
    .execute(&mut *tx)
    .await;
    if let Err(source) = inserted {
        if unique_violation(&source) {
            return Err(DomainFailure::AlreadyExists.into());
        }
        return Err(database("insert policy", source));
    }
    replace_targets(
        &mut tx,
        value.organization_id,
        value.policy_id,
        value.targets,
    )
    .await?;
    let record = policy_tx(&mut tx, value.organization_id, value.policy_id).await?;
    finish_command(&mut tx, command, &record).await?;
    commit(tx, "commit create policy").await?;
    Ok(record)
}

pub(crate) async fn update_policy(
    postgres: &OwnedPostgres,
    command: &Command<'_>,
    patch: &PolicyPatch<'_>,
) -> Result<PolicyRecord, StorageError> {
    let mut tx = begin(postgres, "begin update policy").await?;
    if let Some(replay) = admit_command(&mut tx, command).await? {
        commit(tx, "commit update policy replay").await?;
        return Ok(replay);
    }
    let row = sqlx::query(
        "SELECT revision,archived FROM sla_policies WHERE organization_id=$1 AND policy_id=$2 FOR UPDATE",
    )
    .bind(patch.organization_id)
    .bind(patch.policy_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|source| database("lock policy", source))?
    .ok_or(DomainFailure::NotFound)?;
    let revision: i64 = row
        .try_get("revision")
        .map_err(row_error("read policy revision"))?;
    let archived: bool = row
        .try_get("archived")
        .map_err(row_error("read policy archive"))?;
    if archived {
        return Err(DomainFailure::Archived.into());
    }
    if revision != patch.expected_revision {
        return Err(DomainFailure::RevisionConflict.into());
    }
    sqlx::query(
        "UPDATE sla_policies SET name=COALESCE($3,name),revision=revision+1,updated_at=clock_timestamp() WHERE organization_id=$1 AND policy_id=$2",
    )
    .bind(patch.organization_id)
    .bind(patch.policy_id)
    .bind(patch.name)
    .execute(&mut *tx)
    .await
    .map_err(|source| database("update policy", source))?;
    if let Some(targets) = patch.targets {
        replace_targets(&mut tx, patch.organization_id, patch.policy_id, targets).await?;
    }
    let record = policy_tx(&mut tx, patch.organization_id, patch.policy_id).await?;
    finish_command(&mut tx, command, &record).await?;
    commit(tx, "commit update policy").await?;
    Ok(record)
}

pub(crate) async fn archive_policy(
    postgres: &OwnedPostgres,
    command: &Command<'_>,
    organization_id: &str,
    policy_id: &str,
    expected_revision: i64,
) -> Result<PolicyRecord, StorageError> {
    let mut tx = begin(postgres, "begin archive policy").await?;
    if let Some(replay) = admit_command(&mut tx, command).await? {
        commit(tx, "commit archive policy replay").await?;
        return Ok(replay);
    }
    let row = sqlx::query(
        "SELECT revision,archived FROM sla_policies WHERE organization_id=$1 AND policy_id=$2 FOR UPDATE",
    )
    .bind(organization_id)
    .bind(policy_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|source| database("lock policy for archive", source))?
    .ok_or(DomainFailure::NotFound)?;
    let revision: i64 = row
        .try_get("revision")
        .map_err(row_error("read archive revision"))?;
    let archived: bool = row
        .try_get("archived")
        .map_err(row_error("read archive state"))?;
    if archived || revision != expected_revision {
        return Err(if archived {
            DomainFailure::Archived
        } else {
            DomainFailure::RevisionConflict
        }
        .into());
    }
    sqlx::query(
        "UPDATE sla_policies SET archived=TRUE,archived_at=clock_timestamp(),updated_at=clock_timestamp(),revision=revision+1 WHERE organization_id=$1 AND policy_id=$2",
    )
    .bind(organization_id)
    .bind(policy_id)
    .execute(&mut *tx)
    .await
    .map_err(|source| database("archive policy", source))?;
    let record = policy_tx(&mut tx, organization_id, policy_id).await?;
    finish_command(&mut tx, command, &record).await?;
    commit(tx, "commit archive policy").await?;
    Ok(record)
}

pub(crate) async fn get_policy(
    postgres: &OwnedPostgres,
    organization_id: &str,
    policy_id: &str,
) -> Result<PolicyRecord, StorageError> {
    let row = sqlx::query("SELECT * FROM sla_policies WHERE organization_id=$1 AND policy_id=$2")
        .bind(organization_id)
        .bind(policy_id)
        .fetch_optional(postgres.pool())
        .await
        .map_err(|source| database("get policy", source))?
        .ok_or(DomainFailure::NotFound)?;
    let targets = target_rows_pool(postgres, organization_id, policy_id).await?;
    policy_from_row(&row, targets)
}

pub(crate) async fn list_policies(
    postgres: &OwnedPostgres,
    organization_id: &str,
    include_archived: bool,
    after: Option<&str>,
    limit: i64,
) -> Result<PolicyListRecord, StorageError> {
    let limit_usize = usize::try_from(limit).unwrap_or_default();
    let rows = sqlx::query(
        "SELECT * FROM sla_policies WHERE organization_id=$1 AND ($2 OR NOT archived) AND policy_id>COALESCE($3,'') ORDER BY policy_id LIMIT $4",
    )
    .bind(organization_id)
    .bind(include_archived)
    .bind(after)
    .bind(limit + 1)
    .fetch_all(postgres.pool())
    .await
    .map_err(|source| database("list policies", source))?;
    let has_more = rows.len() > limit_usize;
    let mut policies = Vec::with_capacity(rows.len().min(limit_usize));
    for row in rows.into_iter().take(limit_usize) {
        let policy_id: String = row
            .try_get("policy_id")
            .map_err(row_error("read policy id"))?;
        let targets = target_rows_pool(postgres, organization_id, &policy_id).await?;
        policies.push(policy_from_row(&row, targets)?);
    }
    let next_after_policy_id = has_more
        .then(|| policies.last().map(|policy| policy.policy_id.clone()))
        .flatten();
    Ok(PolicyListRecord {
        policies,
        next_after_policy_id,
    })
}

#[allow(clippy::too_many_lines)]
pub(crate) async fn observe_case_snapshot(
    postgres: &OwnedPostgres,
    caller: &str,
    request_hash: &[u8],
    value: &CaseSnapshot<'_>,
    reconciliation_interval_seconds: i64,
) -> Result<ObservationRecord, StorageError> {
    let mut tx = begin(postgres, "begin case snapshot observation").await?;
    if let Some(mut replay) = admit_observation(
        &mut tx,
        caller,
        value.observation_id,
        "case_snapshot",
        value.organization_id,
        value.case_id,
        value.source_case_revision,
        None,
        request_hash,
    )
    .await?
    {
        replay.replayed = true;
        replay.schedule =
            schedule_for_response(&mut tx, replay.successor_schedule_id.as_deref()).await?;
        commit(tx, "commit snapshot replay").await?;
        return Ok(replay);
    }
    if let Some(row) = sqlx::query(
        "SELECT request_hash,response,status FROM sla_case_observations WHERE observation_kind='case_snapshot' AND organization_id=$1 AND case_id=$2 AND source_case_revision=$3 AND NOT (caller_instance=$4 AND observation_id=$5)",
    )
    .bind(value.organization_id)
    .bind(value.case_id)
    .bind(value.source_case_revision)
    .bind(caller)
    .bind(value.observation_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|source| database("dedupe snapshot fact", source))?
    {
        let existing_hash: Vec<u8> = row.try_get("request_hash").map_err(row_error("read snapshot fact hash"))?;
        if existing_hash != request_hash {
            return Err(DomainFailure::ObservationConflict.into());
        }
        let status: String = row
            .try_get("status")
            .map_err(row_error("read snapshot fact status"))?;
        if status != "completed" {
            return Err(DomainFailure::ObservationConflict.into());
        }
        let response: Option<serde_json::Value> = row.try_get("response").map_err(row_error("read snapshot fact receipt"))?;
        let mut replay: ObservationRecord = decode_receipt(response)?;
        replay.replayed = true;
        replay.schedule = schedule_for_response(&mut tx, replay.successor_schedule_id.as_deref()).await?;
        finish_observation(&mut tx, caller, value.observation_id, &replay).await?;
        commit(tx, "commit equivalent snapshot fact").await?;
        return Ok(replay);
    }

    let policy = sqlx::query(
        "SELECT revision,archived FROM sla_policies WHERE organization_id=$1 AND policy_id=$2",
    )
    .bind(value.organization_id)
    .bind(value.policy_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|source| database("read snapshot policy", source))?
    .ok_or(DomainFailure::PolicyNotFound)?;
    let policy_archived: bool = policy
        .try_get("archived")
        .map_err(row_error("read policy archived"))?;
    if policy_archived {
        return Err(DomainFailure::PolicyArchived.into());
    }
    let policy_revision: i64 = policy
        .try_get("revision")
        .map_err(row_error("read policy revision"))?;
    let target = sqlx::query(
        "SELECT first_response_seconds,resolution_seconds FROM sla_policy_targets WHERE organization_id=$1 AND policy_id=$2 AND priority=$3",
    )
    .bind(value.organization_id)
    .bind(value.policy_id)
    .bind(value.priority)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|source| database("read snapshot target", source))?
    .ok_or(DomainFailure::PolicyNotFound)?;
    let first_response_seconds: i64 = target
        .try_get("first_response_seconds")
        .map_err(row_error("read first response target"))?;
    let resolution_seconds: i64 = target
        .try_get("resolution_seconds")
        .map_err(row_error("read resolution target"))?;

    let existing = sqlx::query(
        "SELECT source_case_revision,source_updated_at,policy_id,policy_revision,priority FROM sla_cases WHERE organization_id=$1 AND case_id=$2 FOR UPDATE",
    )
    .bind(value.organization_id)
    .bind(value.case_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|source| database("lock observed case", source))?;
    let mut clocks_changed = 0_i64;
    if let Some(row) = existing {
        let stored_updated_at: OffsetDateTime = row
            .try_get("source_updated_at")
            .map_err(row_error("read case updated_at"))?;
        let stored_policy_id: String = row
            .try_get("policy_id")
            .map_err(row_error("read pinned policy"))?;
        let stored_priority: String = row
            .try_get("priority")
            .map_err(row_error("read pinned priority"))?;
        if stored_policy_id != value.policy_id || stored_priority != value.priority {
            return Err(DomainFailure::ObservationConflict.into());
        }
        if value.updated_at < stored_updated_at {
            return Err(DomainFailure::StaleObservation.into());
        }
        if value.updated_at == stored_updated_at {
            return Err(DomainFailure::ObservationConflict.into());
        }
        sqlx::query(
            "UPDATE sla_cases SET state=$3,source_case_revision=$4,source_updated_at=$5,source_resolved_at=$6,source_closed_at=$7,observed_at=clock_timestamp() WHERE organization_id=$1 AND case_id=$2",
        )
        .bind(value.organization_id)
        .bind(value.case_id)
        .bind(value.state)
        .bind(value.source_case_revision)
        .bind(value.updated_at)
        .bind(value.resolved_at)
        .bind(value.closed_at)
        .execute(&mut *tx)
        .await
        .map_err(|source| database("update observed case", source))?;
    } else {
        sqlx::query(
            "INSERT INTO sla_cases(organization_id,case_id,policy_id,policy_revision,priority,state,source_case_revision,source_created_at,source_updated_at,source_resolved_at,source_closed_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
        )
        .bind(value.organization_id)
        .bind(value.case_id)
        .bind(value.policy_id)
        .bind(policy_revision)
        .bind(value.priority)
        .bind(value.state)
        .bind(value.source_case_revision)
        .bind(value.created_at)
        .bind(value.updated_at)
        .bind(value.resolved_at)
        .bind(value.closed_at)
        .execute(&mut *tx)
        .await
        .map_err(|source| database("insert observed case", source))?;
        insert_clock(
            &mut tx,
            value,
            policy_revision,
            "first_response",
            first_response_seconds,
        )
        .await?;
        insert_clock(
            &mut tx,
            value,
            policy_revision,
            "resolution",
            resolution_seconds,
        )
        .await?;
        clocks_changed += 2;
    }

    let completion_at = value.resolved_at.or(value.closed_at);
    if let Some(completion_at) = completion_at {
        let result = sqlx::query(
            "UPDATE sla_clocks SET status='met',satisfied_at=$3,next_fire_at=NULL,revision=revision+1,updated_at=clock_timestamp() WHERE organization_id=$1 AND case_id=$2 AND kind='resolution' AND status='running'",
        )
        .bind(value.organization_id)
        .bind(value.case_id)
        .bind(completion_at)
        .execute(&mut *tx)
        .await
        .map_err(|source| database("satisfy resolution clock", source))?;
        clocks_changed += i64::try_from(result.rows_affected()).unwrap_or(i64::MAX);
        let result = sqlx::query(
            "UPDATE sla_clocks SET status='canceled',next_fire_at=NULL,revision=revision+1,updated_at=clock_timestamp() WHERE organization_id=$1 AND case_id=$2 AND kind='first_response' AND status='running'",
        )
        .bind(value.organization_id)
        .bind(value.case_id)
        .execute(&mut *tx)
        .await
        .map_err(|source| database("cancel response clock for completed case", source))?;
        clocks_changed += i64::try_from(result.rows_affected()).unwrap_or(i64::MAX);
    }

    let schedule = ensure_schedule(
        &mut tx,
        value.observation_id,
        value.updated_at,
        reconciliation_interval_seconds,
    )
    .await?;
    let response = ObservationRecord {
        accepted: true,
        replayed: false,
        case_id: value.case_id.to_owned(),
        source_case_revision: value.source_case_revision.to_owned(),
        clocks_changed,
        next_fire_at: Some(schedule.available_at.clone()),
        successor_schedule_id: Some(schedule.schedule_id.clone()),
        successor_status: "pending_external_worker".to_owned(),
        schedule: Some(schedule),
    };
    finish_observation(&mut tx, caller, value.observation_id, &response).await?;
    commit(tx, "commit case snapshot observation").await?;
    Ok(response)
}

#[allow(clippy::too_many_lines)]
pub(crate) async fn observe_case_message(
    postgres: &OwnedPostgres,
    caller: &str,
    request_hash: &[u8],
    value: &CaseMessage<'_>,
    reconciliation_interval_seconds: i64,
) -> Result<ObservationRecord, StorageError> {
    let mut tx = begin(postgres, "begin case message observation").await?;
    if let Some(mut replay) = admit_observation(
        &mut tx,
        caller,
        value.observation_id,
        "case_message",
        value.organization_id,
        value.case_id,
        value.source_case_revision,
        Some(value.message_id),
        request_hash,
    )
    .await?
    {
        replay.replayed = true;
        replay.schedule =
            schedule_for_response(&mut tx, replay.successor_schedule_id.as_deref()).await?;
        commit(tx, "commit message replay").await?;
        return Ok(replay);
    }
    if let Some(row) = sqlx::query(
        "SELECT request_hash,response,status FROM sla_case_observations WHERE observation_kind='case_message' AND organization_id=$1 AND case_id=$2 AND source_fact_id=$3 AND NOT (caller_instance=$4 AND observation_id=$5)",
    )
    .bind(value.organization_id)
    .bind(value.case_id)
    .bind(value.message_id)
    .bind(caller)
    .bind(value.observation_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|source| database("dedupe message observation fact", source))?
    {
        let existing_hash: Vec<u8> = row
            .try_get("request_hash")
            .map_err(row_error("read message observation hash"))?;
        if existing_hash != request_hash {
            return Err(DomainFailure::ObservationConflict.into());
        }
        let status: String = row
            .try_get("status")
            .map_err(row_error("read message observation status"))?;
        if status != "completed" {
            return Err(DomainFailure::ObservationConflict.into());
        }
        let response: Option<serde_json::Value> = row
            .try_get("response")
            .map_err(row_error("read message observation receipt"))?;
        let mut replay: ObservationRecord = decode_receipt(response)?;
        replay.replayed = true;
        replay.schedule =
            schedule_for_response(&mut tx, replay.successor_schedule_id.as_deref()).await?;
        finish_observation(&mut tx, caller, value.observation_id, &replay).await?;
        commit(tx, "commit equivalent message fact").await?;
        return Ok(replay);
    }
    let case_exists =
        sqlx::query("SELECT 1 FROM sla_cases WHERE organization_id=$1 AND case_id=$2 FOR UPDATE")
            .bind(value.organization_id)
            .bind(value.case_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|source| database("read case for message", source))?
            .is_some();
    if !case_exists {
        return Err(DomainFailure::CaseNotObserved.into());
    }
    if let Some(row) = sqlx::query(
        "SELECT request_hash FROM sla_case_messages WHERE organization_id=$1 AND case_id=$2 AND message_id=$3",
    )
    .bind(value.organization_id)
    .bind(value.case_id)
    .bind(value.message_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|source| database("dedupe message fact", source))?
    {
        let existing_hash: Vec<u8> = row.try_get("request_hash").map_err(row_error("read message fact hash"))?;
        if existing_hash != request_hash {
            return Err(DomainFailure::ObservationConflict.into());
        }
    } else {
        sqlx::query(
            "INSERT INTO sla_case_messages(organization_id,case_id,message_id,source_case_revision,request_hash,visibility,author_kind,occurred_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)",
        )
        .bind(value.organization_id)
        .bind(value.case_id)
        .bind(value.message_id)
        .bind(value.source_case_revision)
        .bind(request_hash)
        .bind(value.visibility)
        .bind(value.author_kind)
        .bind(value.occurred_at)
        .execute(&mut *tx)
        .await
        .map_err(|source| database("insert message fact", source))?;
    }
    let clocks_changed = if value.visibility == "public" && value.author_kind == "agent" {
        i64::try_from(sqlx::query(
            "UPDATE sla_clocks SET status='met',satisfied_at=$3,next_fire_at=NULL,revision=revision+1,updated_at=clock_timestamp() WHERE organization_id=$1 AND case_id=$2 AND kind='first_response' AND status='running'",
        )
        .bind(value.organization_id)
        .bind(value.case_id)
        .bind(value.occurred_at)
        .execute(&mut *tx)
        .await
        .map_err(|source| database("satisfy response clock", source))?
        .rows_affected()).unwrap_or(i64::MAX)
    } else {
        0
    };
    let schedule = ensure_schedule(
        &mut tx,
        value.observation_id,
        value.occurred_at,
        reconciliation_interval_seconds,
    )
    .await?;
    let response = ObservationRecord {
        accepted: true,
        replayed: false,
        case_id: value.case_id.to_owned(),
        source_case_revision: value.source_case_revision.to_owned(),
        clocks_changed,
        next_fire_at: Some(schedule.available_at.clone()),
        successor_schedule_id: Some(schedule.schedule_id.clone()),
        successor_status: "pending_external_worker".to_owned(),
        schedule: Some(schedule),
    };
    finish_observation(&mut tx, caller, value.observation_id, &response).await?;
    commit(tx, "commit case message observation").await?;
    Ok(response)
}

#[allow(clippy::too_many_lines)]
pub(crate) async fn reconcile(
    postgres: &OwnedPostgres,
    caller: &str,
    run_id: &str,
    request_hash: &[u8],
    observed_at: OffsetDateTime,
    limit: i64,
    reconciliation_interval_seconds: i64,
) -> Result<ReconcileRecord, StorageError> {
    let mut tx = begin(postgres, "begin reconcile").await?;
    if let Some(mut replay) = admit_reconcile(&mut tx, caller, run_id, request_hash).await? {
        replay.replayed = true;
        replay.schedule =
            schedule_for_response(&mut tx, replay.successor_schedule_id.as_deref()).await?;
        commit(tx, "commit reconcile replay").await?;
        return Ok(replay);
    }
    sqlx::query(
        "UPDATE sla_schedule_outbox SET status='consumed',updated_at=clock_timestamp() WHERE available_at<=$1 AND status IN ('pending','enqueued','failed')",
    )
    .bind(observed_at)
    .execute(&mut *tx)
    .await
    .map_err(|source| database("consume due schedules", source))?;
    let due = sqlx::query(
        "SELECT clock_id,organization_id,case_id,kind,target_at,revision FROM sla_clocks WHERE status='running' AND next_fire_at<=$1 ORDER BY next_fire_at,clock_id FOR UPDATE SKIP LOCKED LIMIT $2",
    )
    .bind(observed_at)
    .bind(limit)
    .fetch_all(&mut *tx)
    .await
    .map_err(|source| database("claim due SLA clocks", source))?;
    let processed_clocks = i64::try_from(due.len()).unwrap_or(i64::MAX);
    let mut new_breaches = 0_i64;
    for row in due {
        let clock_id: String = row
            .try_get("clock_id")
            .map_err(row_error("read due clock id"))?;
        let organization_id: String = row
            .try_get("organization_id")
            .map_err(row_error("read due organization"))?;
        let case_id: String = row.try_get("case_id").map_err(row_error("read due case"))?;
        let kind: String = row.try_get("kind").map_err(row_error("read due kind"))?;
        let target_at: OffsetDateTime = row
            .try_get("target_at")
            .map_err(row_error("read due target"))?;
        let old_revision: i64 = row
            .try_get("revision")
            .map_err(row_error("read due revision"))?;
        let updated = sqlx::query(
            "UPDATE sla_clocks SET status='breached',breached_at=target_at,next_fire_at=NULL,revision=revision+1,updated_at=clock_timestamp() WHERE clock_id=$1 AND status='running'",
        )
        .bind(&clock_id)
        .execute(&mut *tx)
        .await
        .map_err(|source| database("mark clock breached", source))?;
        if updated.rows_affected() == 0 {
            continue;
        }
        let breach_id = stable_id("slab", &clock_id);
        let outbox_id = stable_id("slan", &breach_id);
        let inserted = sqlx::query(
            "INSERT INTO sla_breaches(breach_id,organization_id,case_id,clock_id,kind,target_at,breached_at,clock_revision) VALUES($1,$2,$3,$4,$5,$6,$6,$7) ON CONFLICT(clock_id) DO NOTHING",
        )
        .bind(&breach_id)
        .bind(&organization_id)
        .bind(&case_id)
        .bind(&clock_id)
        .bind(&kind)
        .bind(target_at)
        .bind(old_revision + 1)
        .execute(&mut *tx)
        .await
        .map_err(|source| database("insert SLA breach", source))?;
        if inserted.rows_affected() == 0 {
            continue;
        }
        let payload = serde_json::json!({
            "breach_id": breach_id,
            "organization_id": organization_id,
            "case_id": case_id,
            "clock_id": clock_id,
            "kind": kind,
            "target_at": format_time(target_at)?,
        });
        sqlx::query(
            "INSERT INTO sla_notification_outbox(notification_outbox_id,breach_id,payload) VALUES($1,$2,$3) ON CONFLICT(breach_id) DO NOTHING",
        )
        .bind(&outbox_id)
        .bind(&breach_id)
        .bind(payload)
        .execute(&mut *tx)
        .await
        .map_err(|source| database("insert breach notification outbox", source))?;
        new_breaches += 1;
    }
    let schedule = ensure_schedule(
        &mut tx,
        run_id,
        observed_at,
        reconciliation_interval_seconds,
    )
    .await?;
    let response = ReconcileRecord {
        run_id: run_id.to_owned(),
        replayed: false,
        processed_clocks,
        new_breaches,
        next_fire_at: Some(schedule.available_at.clone()),
        successor_schedule_id: Some(schedule.schedule_id.clone()),
        successor_status: "pending_external_worker".to_owned(),
        schedule: Some(schedule),
    };
    finish_reconcile(&mut tx, caller, run_id, &response).await?;
    commit(tx, "commit reconcile").await?;
    Ok(response)
}

pub(crate) async fn arrange_reconcile_successor(
    postgres: &OwnedPostgres,
    run_id: &str,
    observed_at: OffsetDateTime,
    reconciliation_interval_seconds: i64,
) -> Result<ScheduleRecord, StorageError> {
    let mut tx = begin(postgres, "begin reconcile successor arrangement").await?;
    let schedule = ensure_schedule_at(
        &mut tx,
        run_id,
        observed_at + Duration::seconds(reconciliation_interval_seconds),
    )
    .await?;
    commit(tx, "commit reconcile successor arrangement").await?;
    Ok(schedule)
}

pub(crate) async fn get_clock(
    postgres: &OwnedPostgres,
    organization_id: &str,
    case_id: &str,
    kind: &str,
) -> Result<ClockRecord, StorageError> {
    let row =
        sqlx::query("SELECT * FROM sla_clocks WHERE organization_id=$1 AND case_id=$2 AND kind=$3")
            .bind(organization_id)
            .bind(case_id)
            .bind(kind)
            .fetch_optional(postgres.pool())
            .await
            .map_err(|source| database("get SLA clock", source))?
            .ok_or(DomainFailure::NotFound)?;
    clock_from_row(&row)
}

pub(crate) async fn list_clocks(
    postgres: &OwnedPostgres,
    organization_id: &str,
    case_id: Option<&str>,
    status: Option<&str>,
    after: Option<&str>,
    limit: i64,
) -> Result<ClockListRecord, StorageError> {
    let limit_usize = usize::try_from(limit).unwrap_or_default();
    let rows = sqlx::query(
        "SELECT * FROM sla_clocks WHERE organization_id=$1 AND ($2::TEXT IS NULL OR case_id=$2) AND ($3::TEXT IS NULL OR status=$3) AND clock_id>COALESCE($4,'') ORDER BY clock_id LIMIT $5",
    )
    .bind(organization_id)
    .bind(case_id)
    .bind(status)
    .bind(after)
    .bind(limit + 1)
    .fetch_all(postgres.pool())
    .await
    .map_err(|source| database("list SLA clocks", source))?;
    let has_more = rows.len() > limit_usize;
    let clocks = rows
        .into_iter()
        .take(limit_usize)
        .map(|row| clock_from_row(&row))
        .collect::<Result<Vec<_>, _>>()?;
    let next_after_clock_id = has_more
        .then(|| clocks.last().map(|clock| clock.clock_id.clone()))
        .flatten();
    Ok(ClockListRecord {
        clocks,
        next_after_clock_id,
    })
}

pub(crate) async fn list_breaches(
    postgres: &OwnedPostgres,
    organization_id: &str,
    case_id: Option<&str>,
    notification_status: Option<&str>,
    after: Option<&str>,
    limit: i64,
) -> Result<BreachListRecord, StorageError> {
    let limit_usize = usize::try_from(limit).unwrap_or_default();
    let rows = sqlx::query(
        "SELECT b.*,n.notification_outbox_id,n.status AS notification_status,n.attempt_count,n.last_error_code FROM sla_breaches b JOIN sla_notification_outbox n ON n.breach_id=b.breach_id WHERE b.organization_id=$1 AND ($2::TEXT IS NULL OR b.case_id=$2) AND ($3::TEXT IS NULL OR n.status=$3) AND b.breach_id>COALESCE($4,'') ORDER BY b.breach_id LIMIT $5",
    )
    .bind(organization_id)
    .bind(case_id)
    .bind(notification_status)
    .bind(after)
    .bind(limit + 1)
    .fetch_all(postgres.pool())
    .await
    .map_err(|source| database("list SLA breaches", source))?;
    let has_more = rows.len() > limit_usize;
    let breaches = rows
        .into_iter()
        .take(limit_usize)
        .map(|row| breach_from_row(&row))
        .collect::<Result<Vec<_>, _>>()?;
    let next_after_breach_id = has_more
        .then(|| breaches.last().map(|breach| breach.breach_id.clone()))
        .flatten();
    Ok(BreachListRecord {
        breaches,
        next_after_breach_id,
    })
}

pub(crate) async fn mark_schedule_enqueued(
    postgres: &OwnedPostgres,
    schedule_id: &str,
    job_id: &str,
) -> Result<(), StorageError> {
    sqlx::query(
        "UPDATE sla_schedule_outbox SET status='enqueued',job_id=$2,attempt_count=attempt_count+1,last_attempt_at=clock_timestamp(),last_error_code=NULL,updated_at=clock_timestamp() WHERE schedule_id=$1 AND status IN ('pending','failed','enqueued')",
    )
    .bind(schedule_id)
    .bind(job_id)
    .execute(postgres.pool())
    .await
    .map_err(|source| database("record Jobs enqueue", source))?;
    Ok(())
}

pub(crate) async fn mark_schedule_failed(
    postgres: &OwnedPostgres,
    schedule_id: &str,
    error_code: &str,
) -> Result<(), StorageError> {
    sqlx::query(
        "UPDATE sla_schedule_outbox SET status='failed',attempt_count=attempt_count+1,last_attempt_at=clock_timestamp(),last_error_code=$2,updated_at=clock_timestamp() WHERE schedule_id=$1 AND status IN ('pending','failed')",
    )
    .bind(schedule_id)
    .bind(error_code)
    .execute(postgres.pool())
    .await
    .map_err(|source| database("record Jobs enqueue failure", source))?;
    Ok(())
}

async fn replace_targets(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    policy_id: &str,
    targets: &[TargetRecord],
) -> Result<(), StorageError> {
    sqlx::query("DELETE FROM sla_policy_targets WHERE organization_id=$1 AND policy_id=$2")
        .bind(organization_id)
        .bind(policy_id)
        .execute(&mut **tx)
        .await
        .map_err(|source| database("replace policy targets", source))?;
    for target in targets {
        sqlx::query(
            "INSERT INTO sla_policy_targets(organization_id,policy_id,priority,first_response_seconds,resolution_seconds) VALUES($1,$2,$3,$4,$5)",
        )
        .bind(organization_id)
        .bind(policy_id)
        .bind(&target.priority)
        .bind(target.first_response_seconds)
        .bind(target.resolution_seconds)
        .execute(&mut **tx)
        .await
        .map_err(|source| database("insert policy target", source))?;
    }
    Ok(())
}

async fn policy_tx(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    policy_id: &str,
) -> Result<PolicyRecord, StorageError> {
    let row = sqlx::query("SELECT * FROM sla_policies WHERE organization_id=$1 AND policy_id=$2")
        .bind(organization_id)
        .bind(policy_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|source| database("read policy receipt", source))?
        .ok_or(DomainFailure::NotFound)?;
    let rows = sqlx::query(
        "SELECT priority,first_response_seconds,resolution_seconds FROM sla_policy_targets WHERE organization_id=$1 AND policy_id=$2 ORDER BY CASE priority WHEN 'low' THEN 1 WHEN 'normal' THEN 2 WHEN 'high' THEN 3 ELSE 4 END",
    )
    .bind(organization_id)
    .bind(policy_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(|source| database("read policy targets", source))?;
    policy_from_row(&row, target_rows(rows)?)
}

async fn target_rows_pool(
    postgres: &OwnedPostgres,
    organization_id: &str,
    policy_id: &str,
) -> Result<Vec<TargetRecord>, StorageError> {
    let rows = sqlx::query(
        "SELECT priority,first_response_seconds,resolution_seconds FROM sla_policy_targets WHERE organization_id=$1 AND policy_id=$2 ORDER BY CASE priority WHEN 'low' THEN 1 WHEN 'normal' THEN 2 WHEN 'high' THEN 3 ELSE 4 END",
    )
    .bind(organization_id)
    .bind(policy_id)
    .fetch_all(postgres.pool())
    .await
    .map_err(|source| database("read policy targets", source))?;
    target_rows(rows)
}

fn target_rows(rows: Vec<sqlx::postgres::PgRow>) -> Result<Vec<TargetRecord>, StorageError> {
    rows.into_iter()
        .map(|row| {
            Ok(TargetRecord {
                priority: row
                    .try_get("priority")
                    .map_err(row_error("read target priority"))?,
                first_response_seconds: row
                    .try_get("first_response_seconds")
                    .map_err(row_error("read first response seconds"))?,
                resolution_seconds: row
                    .try_get("resolution_seconds")
                    .map_err(row_error("read resolution seconds"))?,
            })
        })
        .collect()
}

fn policy_from_row(
    row: &sqlx::postgres::PgRow,
    targets: Vec<TargetRecord>,
) -> Result<PolicyRecord, StorageError> {
    Ok(PolicyRecord {
        organization_id: row
            .try_get("organization_id")
            .map_err(row_error("read policy organization"))?,
        policy_id: row
            .try_get("policy_id")
            .map_err(row_error("read policy id"))?,
        name: row.try_get("name").map_err(row_error("read policy name"))?,
        business_calendar: row
            .try_get("business_calendar")
            .map_err(row_error("read business calendar"))?,
        targets,
        archived: row
            .try_get("archived")
            .map_err(row_error("read policy archived"))?,
        revision: row
            .try_get::<i64, _>("revision")
            .map_err(row_error("read policy revision"))?
            .to_string(),
        created_at: format_time(
            row.try_get("created_at")
                .map_err(row_error("read policy created_at"))?,
        )?,
        updated_at: format_time(
            row.try_get("updated_at")
                .map_err(row_error("read policy updated_at"))?,
        )?,
        archived_at: format_optional_time(
            row.try_get("archived_at")
                .map_err(row_error("read policy archived_at"))?,
        )?,
    })
}

fn clock_from_row(row: &sqlx::postgres::PgRow) -> Result<ClockRecord, StorageError> {
    Ok(ClockRecord {
        clock_id: row
            .try_get("clock_id")
            .map_err(row_error("read clock id"))?,
        organization_id: row
            .try_get("organization_id")
            .map_err(row_error("read clock organization"))?,
        case_id: row
            .try_get("case_id")
            .map_err(row_error("read clock case"))?,
        policy_id: row
            .try_get("policy_id")
            .map_err(row_error("read clock policy"))?,
        policy_revision: row
            .try_get::<i64, _>("policy_revision")
            .map_err(row_error("read clock policy revision"))?
            .to_string(),
        priority: row
            .try_get("priority")
            .map_err(row_error("read clock priority"))?,
        kind: row.try_get("kind").map_err(row_error("read clock kind"))?,
        target_seconds: row
            .try_get("target_seconds")
            .map_err(row_error("read clock target seconds"))?,
        started_at: format_time(
            row.try_get("started_at")
                .map_err(row_error("read clock started_at"))?,
        )?,
        target_at: format_time(
            row.try_get("target_at")
                .map_err(row_error("read clock target_at"))?,
        )?,
        status: row
            .try_get("status")
            .map_err(row_error("read clock status"))?,
        satisfied_at: format_optional_time(
            row.try_get("satisfied_at")
                .map_err(row_error("read clock satisfied_at"))?,
        )?,
        breached_at: format_optional_time(
            row.try_get("breached_at")
                .map_err(row_error("read clock breached_at"))?,
        )?,
        next_fire_at: format_optional_time(
            row.try_get("next_fire_at")
                .map_err(row_error("read clock next_fire_at"))?,
        )?,
        revision: row
            .try_get::<i64, _>("revision")
            .map_err(row_error("read clock revision"))?
            .to_string(),
        updated_at: format_time(
            row.try_get("updated_at")
                .map_err(row_error("read clock updated_at"))?,
        )?,
    })
}

fn breach_from_row(row: &sqlx::postgres::PgRow) -> Result<BreachRecord, StorageError> {
    Ok(BreachRecord {
        breach_id: row
            .try_get("breach_id")
            .map_err(row_error("read breach id"))?,
        organization_id: row
            .try_get("organization_id")
            .map_err(row_error("read breach organization"))?,
        case_id: row
            .try_get("case_id")
            .map_err(row_error("read breach case"))?,
        clock_id: row
            .try_get("clock_id")
            .map_err(row_error("read breach clock"))?,
        kind: row.try_get("kind").map_err(row_error("read breach kind"))?,
        target_at: format_time(
            row.try_get("target_at")
                .map_err(row_error("read breach target_at"))?,
        )?,
        breached_at: format_time(
            row.try_get("breached_at")
                .map_err(row_error("read breached_at"))?,
        )?,
        clock_revision: row
            .try_get::<i64, _>("clock_revision")
            .map_err(row_error("read breach clock revision"))?
            .to_string(),
        notification_outbox_id: row
            .try_get("notification_outbox_id")
            .map_err(row_error("read notification outbox id"))?,
        notification_status: row
            .try_get("notification_status")
            .map_err(row_error("read notification status"))?,
        notification_attempts: i64::from(
            row.try_get::<i32, _>("attempt_count")
                .map_err(row_error("read notification attempts"))?,
        ),
        notification_last_error_code: row
            .try_get("last_error_code")
            .map_err(row_error("read notification error"))?,
    })
}

async fn insert_clock(
    tx: &mut Transaction<'_, Postgres>,
    case: &CaseSnapshot<'_>,
    policy_revision: i64,
    kind: &str,
    target_seconds: i64,
) -> Result<(), StorageError> {
    let clock_id = stable_id(
        "slac",
        &format!("{}\u{0}{}\u{0}{kind}", case.organization_id, case.case_id),
    );
    let target_at = case.created_at + Duration::seconds(target_seconds);
    sqlx::query(
        "INSERT INTO sla_clocks(clock_id,organization_id,case_id,policy_id,policy_revision,priority,kind,target_seconds,started_at,target_at,status,next_fire_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'running',$10)",
    )
    .bind(clock_id)
    .bind(case.organization_id)
    .bind(case.case_id)
    .bind(case.policy_id)
    .bind(policy_revision)
    .bind(case.priority)
    .bind(kind)
    .bind(target_seconds)
    .bind(case.created_at)
    .bind(target_at)
    .execute(&mut **tx)
    .await
    .map_err(|source| database("insert SLA clock", source))?;
    Ok(())
}

async fn admit_command<T: DeserializeOwned>(
    tx: &mut Transaction<'_, Postgres>,
    command: &Command<'_>,
) -> Result<Option<T>, StorageError> {
    let row = sqlx::query(
        "SELECT request_hash,status,response FROM sla_policy_commands WHERE caller_instance=$1 AND actor_subject=$2 AND operation=$3 AND idempotency_key=$4 FOR UPDATE",
    )
    .bind(command.caller)
    .bind(command.actor)
    .bind(command.operation)
    .bind(command.key)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|source| database("read policy command receipt", source))?;
    if let Some(row) = row {
        let hash: Vec<u8> = row
            .try_get("request_hash")
            .map_err(row_error("read command hash"))?;
        if hash != command.hash {
            return Err(DomainFailure::IdempotencyConflict.into());
        }
        let status: String = row
            .try_get("status")
            .map_err(row_error("read command status"))?;
        if status != "completed" {
            return Err(DomainFailure::OperationInProgress.into());
        }
        let response: Option<serde_json::Value> = row
            .try_get("response")
            .map_err(row_error("read command response"))?;
        return Ok(Some(decode_receipt(response)?));
    }
    let inserted = sqlx::query(
        "INSERT INTO sla_policy_commands(caller_instance,actor_subject,operation,idempotency_key,request_hash,status) VALUES($1,$2,$3,$4,$5,'processing') ON CONFLICT DO NOTHING",
    )
    .bind(command.caller)
    .bind(command.actor)
    .bind(command.operation)
    .bind(command.key)
    .bind(command.hash)
    .execute(&mut **tx)
    .await
    .map_err(|source| database("admit policy command", source))?;
    if inserted.rows_affected() == 0 {
        let row = sqlx::query(
            "SELECT request_hash,status,response FROM sla_policy_commands WHERE caller_instance=$1 AND actor_subject=$2 AND operation=$3 AND idempotency_key=$4 FOR UPDATE",
        )
        .bind(command.caller)
        .bind(command.actor)
        .bind(command.operation)
        .bind(command.key)
        .fetch_one(&mut **tx)
        .await
        .map_err(|source| database("read concurrent policy command", source))?;
        let hash: Vec<u8> = row
            .try_get("request_hash")
            .map_err(row_error("read concurrent command hash"))?;
        if hash != command.hash {
            return Err(DomainFailure::IdempotencyConflict.into());
        }
        let status: String = row
            .try_get("status")
            .map_err(row_error("read concurrent command status"))?;
        if status != "completed" {
            return Err(DomainFailure::OperationInProgress.into());
        }
        let response: Option<serde_json::Value> = row
            .try_get("response")
            .map_err(row_error("read concurrent command response"))?;
        return Ok(Some(decode_receipt(response)?));
    }
    Ok(None)
}

async fn finish_command<T: Serialize>(
    tx: &mut Transaction<'_, Postgres>,
    command: &Command<'_>,
    response: &T,
) -> Result<(), StorageError> {
    sqlx::query(
        "UPDATE sla_policy_commands SET response=$5,status='completed',updated_at=clock_timestamp() WHERE caller_instance=$1 AND actor_subject=$2 AND operation=$3 AND idempotency_key=$4",
    )
    .bind(command.caller)
    .bind(command.actor)
    .bind(command.operation)
    .bind(command.key)
    .bind(serde_json::to_value(response)?)
    .execute(&mut **tx)
    .await
    .map_err(|source| database("finish policy command", source))?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn admit_observation(
    tx: &mut Transaction<'_, Postgres>,
    caller: &str,
    observation_id: &str,
    observation_kind: &str,
    organization_id: &str,
    case_id: &str,
    source_case_revision: &str,
    source_fact_id: Option<&str>,
    request_hash: &[u8],
) -> Result<Option<ObservationRecord>, StorageError> {
    let row = sqlx::query(
        "SELECT request_hash,status,response FROM sla_case_observations WHERE caller_instance=$1 AND observation_id=$2 FOR UPDATE",
    )
    .bind(caller)
    .bind(observation_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|source| database("read observation receipt", source))?;
    if let Some(row) = row {
        let hash: Vec<u8> = row
            .try_get("request_hash")
            .map_err(row_error("read observation hash"))?;
        if hash != request_hash {
            return Err(DomainFailure::ObservationConflict.into());
        }
        let status: String = row
            .try_get("status")
            .map_err(row_error("read observation status"))?;
        if status != "completed" {
            return Err(DomainFailure::ObservationConflict.into());
        }
        let response: Option<serde_json::Value> = row
            .try_get("response")
            .map_err(row_error("read observation response"))?;
        return Ok(Some(decode_receipt(response)?));
    }
    let inserted = sqlx::query(
        "INSERT INTO sla_case_observations(caller_instance,observation_id,observation_kind,organization_id,case_id,source_case_revision,source_fact_id,request_hash,status) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'processing') ON CONFLICT DO NOTHING",
    )
    .bind(caller)
    .bind(observation_id)
    .bind(observation_kind)
    .bind(organization_id)
    .bind(case_id)
    .bind(source_case_revision)
    .bind(source_fact_id)
    .bind(request_hash)
    .execute(&mut **tx)
    .await
    .map_err(|source| database("admit case observation", source))?;
    if inserted.rows_affected() == 0 {
        let row = sqlx::query(
            "SELECT request_hash,status,response FROM sla_case_observations WHERE caller_instance=$1 AND observation_id=$2 FOR UPDATE",
        )
        .bind(caller)
        .bind(observation_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|source| database("read concurrent observation receipt", source))?;
        if let Some(row) = row {
            let hash: Vec<u8> = row
                .try_get("request_hash")
                .map_err(row_error("read concurrent observation hash"))?;
            if hash != request_hash {
                return Err(DomainFailure::ObservationConflict.into());
            }
            let status: String = row
                .try_get("status")
                .map_err(row_error("read concurrent observation status"))?;
            if status != "completed" {
                return Err(DomainFailure::ObservationConflict.into());
            }
            let response: Option<serde_json::Value> = row
                .try_get("response")
                .map_err(row_error("read concurrent observation response"))?;
            return Ok(Some(decode_receipt(response)?));
        }
    }
    Ok(None)
}

async fn finish_observation(
    tx: &mut Transaction<'_, Postgres>,
    caller: &str,
    observation_id: &str,
    response: &ObservationRecord,
) -> Result<(), StorageError> {
    sqlx::query(
        "UPDATE sla_case_observations SET response=$3,status='completed',updated_at=clock_timestamp() WHERE caller_instance=$1 AND observation_id=$2",
    )
    .bind(caller)
    .bind(observation_id)
    .bind(serde_json::to_value(response)?)
    .execute(&mut **tx)
    .await
    .map_err(|source| database("finish case observation", source))?;
    Ok(())
}

async fn admit_reconcile(
    tx: &mut Transaction<'_, Postgres>,
    caller: &str,
    run_id: &str,
    request_hash: &[u8],
) -> Result<Option<ReconcileRecord>, StorageError> {
    let row = sqlx::query(
        "SELECT request_hash,status,response FROM sla_reconcile_runs WHERE caller_instance=$1 AND run_id=$2 FOR UPDATE",
    )
    .bind(caller)
    .bind(run_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|source| database("read reconcile receipt", source))?;
    if let Some(row) = row {
        let hash: Vec<u8> = row
            .try_get("request_hash")
            .map_err(row_error("read reconcile hash"))?;
        if hash != request_hash {
            return Err(DomainFailure::RunConflict.into());
        }
        let status: String = row
            .try_get("status")
            .map_err(row_error("read reconcile status"))?;
        if status != "completed" {
            return Err(DomainFailure::RunConflict.into());
        }
        let response: Option<serde_json::Value> = row
            .try_get("response")
            .map_err(row_error("read reconcile response"))?;
        return Ok(Some(decode_receipt(response)?));
    }
    let inserted = sqlx::query(
        "INSERT INTO sla_reconcile_runs(caller_instance,run_id,request_hash,status) VALUES($1,$2,$3,'processing') ON CONFLICT DO NOTHING",
    )
    .bind(caller)
    .bind(run_id)
    .bind(request_hash)
    .execute(&mut **tx)
    .await
    .map_err(|source| database("admit reconcile run", source))?;
    if inserted.rows_affected() == 0 {
        let row = sqlx::query(
            "SELECT request_hash,status,response FROM sla_reconcile_runs WHERE caller_instance=$1 AND run_id=$2 FOR UPDATE",
        )
        .bind(caller)
        .bind(run_id)
        .fetch_one(&mut **tx)
        .await
        .map_err(|source| database("read concurrent reconcile run", source))?;
        let hash: Vec<u8> = row
            .try_get("request_hash")
            .map_err(row_error("read concurrent reconcile hash"))?;
        if hash != request_hash {
            return Err(DomainFailure::RunConflict.into());
        }
        let status: String = row
            .try_get("status")
            .map_err(row_error("read concurrent reconcile status"))?;
        if status != "completed" {
            return Err(DomainFailure::RunConflict.into());
        }
        let response: Option<serde_json::Value> = row
            .try_get("response")
            .map_err(row_error("read concurrent reconcile response"))?;
        return Ok(Some(decode_receipt(response)?));
    }
    Ok(None)
}

async fn finish_reconcile(
    tx: &mut Transaction<'_, Postgres>,
    caller: &str,
    run_id: &str,
    response: &ReconcileRecord,
) -> Result<(), StorageError> {
    sqlx::query(
        "UPDATE sla_reconcile_runs SET response=$3,status='completed',updated_at=clock_timestamp() WHERE caller_instance=$1 AND run_id=$2",
    )
    .bind(caller)
    .bind(run_id)
    .bind(serde_json::to_value(response)?)
    .execute(&mut **tx)
    .await
    .map_err(|source| database("finish reconcile run", source))?;
    Ok(())
}

async fn ensure_schedule(
    tx: &mut Transaction<'_, Postgres>,
    anchor: &str,
    observed_at: OffsetDateTime,
    reconciliation_interval_seconds: i64,
) -> Result<ScheduleRecord, StorageError> {
    let next_due: Option<OffsetDateTime> = sqlx::query_scalar(
        "SELECT MIN(next_fire_at) FROM sla_clocks WHERE status='running' AND next_fire_at IS NOT NULL",
    )
    .fetch_one(&mut **tx)
    .await
    .map_err(|source| database("read next SLA fire time", source))?;
    let heartbeat = observed_at + Duration::seconds(reconciliation_interval_seconds);
    let available_at = next_due.map_or(heartbeat, |due| due.min(heartbeat));
    ensure_schedule_at(tx, anchor, available_at).await
}

async fn ensure_schedule_at(
    tx: &mut Transaction<'_, Postgres>,
    anchor: &str,
    available_at: OffsetDateTime,
) -> Result<ScheduleRecord, StorageError> {
    let idempotency_key = format!("support-sla/{}", stable_id("anchor", anchor));
    let schedule_id = stable_id("slas", &idempotency_key);
    sqlx::query(
        "INSERT INTO sla_schedule_outbox(schedule_id,idempotency_key,available_at) VALUES($1,$2,$3) ON CONFLICT(idempotency_key) DO UPDATE SET available_at=LEAST(sla_schedule_outbox.available_at,EXCLUDED.available_at),status=CASE WHEN sla_schedule_outbox.status='failed' THEN 'pending' ELSE sla_schedule_outbox.status END,updated_at=clock_timestamp() WHERE sla_schedule_outbox.status IN ('pending','failed')",
    )
    .bind(&schedule_id)
    .bind(&idempotency_key)
    .bind(available_at)
    .execute(&mut **tx)
    .await
    .map_err(|source| database("arrange successor schedule", source))?;
    schedule_tx(tx, &schedule_id).await
}

async fn schedule_for_response(
    tx: &mut Transaction<'_, Postgres>,
    schedule_id: Option<&str>,
) -> Result<Option<ScheduleRecord>, StorageError> {
    match schedule_id {
        Some(schedule_id) => schedule_tx(tx, schedule_id).await.map(Some),
        None => Ok(None),
    }
}

async fn schedule_tx(
    tx: &mut Transaction<'_, Postgres>,
    schedule_id: &str,
) -> Result<ScheduleRecord, StorageError> {
    let row = sqlx::query("SELECT schedule_id,idempotency_key,available_at,status,job_id FROM sla_schedule_outbox WHERE schedule_id=$1")
        .bind(schedule_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|source| database("read successor schedule", source))?
        .ok_or(DomainFailure::NotFound)?;
    Ok(ScheduleRecord {
        schedule_id: row
            .try_get("schedule_id")
            .map_err(row_error("read schedule id"))?,
        idempotency_key: row
            .try_get("idempotency_key")
            .map_err(row_error("read schedule key"))?,
        available_at: format_time(
            row.try_get("available_at")
                .map_err(row_error("read schedule time"))?,
        )?,
        status: row
            .try_get("status")
            .map_err(row_error("read schedule status"))?,
        job_id: row
            .try_get("job_id")
            .map_err(row_error("read schedule job"))?,
    })
}

fn decode_receipt<T: DeserializeOwned>(
    response: Option<serde_json::Value>,
) -> Result<T, StorageError> {
    Ok(serde_json::from_value(
        response.unwrap_or(serde_json::Value::Null),
    )?)
}

async fn begin<'a>(
    postgres: &'a OwnedPostgres,
    operation: &'static str,
) -> Result<Transaction<'a, Postgres>, StorageError> {
    postgres
        .pool()
        .begin()
        .await
        .map_err(|source| database(operation, source))
}

async fn commit(
    tx: Transaction<'_, Postgres>,
    operation: &'static str,
) -> Result<(), StorageError> {
    tx.commit()
        .await
        .map_err(|source| database(operation, source))
}

fn database(operation: &'static str, source: sqlx::Error) -> StorageError {
    StorageError::Database { operation, source }
}

fn row_error(operation: &'static str) -> impl FnOnce(sqlx::Error) -> StorageError {
    move |source| database(operation, source)
}

fn unique_violation(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .is_some_and(|code| code == "23505")
}

fn stable_id(prefix: &str, material: &str) -> String {
    let digest = Sha256::digest(material.as_bytes());
    format!("{prefix}_{digest:x}")
}

fn format_time(value: OffsetDateTime) -> Result<String, StorageError> {
    Ok(value.format(&Rfc3339)?)
}

fn format_optional_time(value: Option<OffsetDateTime>) -> Result<Option<String>, StorageError> {
    value.map(format_time).transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_ids_are_repeatable_and_namespaced() {
        assert_eq!(
            stable_id("slac", "org\0case\0resolution"),
            stable_id("slac", "org\0case\0resolution")
        );
        assert!(stable_id("slab", "clock").starts_with("slab_"));
        assert_ne!(stable_id("slab", "clock"), stable_id("slan", "clock"));
    }

    #[test]
    fn target_record_wire_is_stable() {
        let target = TargetRecord {
            priority: "urgent".to_owned(),
            first_response_seconds: 300,
            resolution_seconds: 3_600,
        };
        assert_eq!(
            serde_json::to_value(target).unwrap(),
            serde_json::json!({
                "priority": "urgent",
                "first_response_seconds": 300,
                "resolution_seconds": 3600
            })
        );
    }
}
