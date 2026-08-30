use lenso_postgres_kit::OwnedPostgres;
use time::{Duration, OffsetDateTime};

use crate::{SupportSlaOperator, schema, storage};

const TEST_SCHEMA: &str = "support_sla_acceptance";
static POSTGRES_ACCEPTANCE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test]
#[ignore = "requires LENSO_SUPPORT_SLA_POSTGRES_TEST_URL and exclusive ownership of support_sla_acceptance"]
#[allow(clippy::too_many_lines)]
async fn policy_observation_reconcile_and_outbox_round_trip() {
    let _lock = POSTGRES_ACCEPTANCE_LOCK.lock().await;
    let database_url = std::env::var("LENSO_SUPPORT_SLA_POSTGRES_TEST_URL")
        .expect("LENSO_SUPPORT_SLA_POSTGRES_TEST_URL must be set");
    let admin = sqlx::PgPool::connect(&database_url).await.unwrap();
    sqlx::query("DROP SCHEMA IF EXISTS support_sla_acceptance CASCADE")
        .execute(&admin)
        .await
        .unwrap();
    SupportSlaOperator::setup(&database_url, TEST_SCHEMA)
        .await
        .unwrap();
    let postgres = OwnedPostgres::prepare(&database_url, schema::schema_plan(TEST_SCHEMA).unwrap())
        .await
        .unwrap();

    let targets = vec![
        storage::TargetRecord {
            priority: "low".to_owned(),
            first_response_seconds: 3_600,
            resolution_seconds: 86_400,
        },
        storage::TargetRecord {
            priority: "normal".to_owned(),
            first_response_seconds: 1_800,
            resolution_seconds: 43_200,
        },
        storage::TargetRecord {
            priority: "high".to_owned(),
            first_response_seconds: 900,
            resolution_seconds: 14_400,
        },
        storage::TargetRecord {
            priority: "urgent".to_owned(),
            first_response_seconds: 300,
            resolution_seconds: 3_600,
        },
    ];
    let command = storage::Command {
        caller: "acceptance-admin",
        actor: "usr_acceptance",
        operation: "create_policy",
        key: "policy-command-1",
        hash: b"policy-hash-1",
    };
    let policy = storage::create_policy(
        &postgres,
        &command,
        &storage::PolicyCreate {
            organization_id: "org_acceptance",
            policy_id: "policy_default",
            name: "Default SLA",
            targets: &targets,
        },
    )
    .await
    .unwrap();
    assert_eq!(policy.revision, "1");

    let created_at = OffsetDateTime::now_utc() - Duration::days(2);
    let observation = storage::observe_case_snapshot(
        &postgres,
        "acceptance-observer",
        b"case-hash-1",
        &storage::CaseSnapshot {
            observation_id: "case-observation-1",
            organization_id: "org_acceptance",
            case_id: "case_opaque_1",
            source_case_revision: "case-revision-1",
            policy_id: "policy_default",
            priority: "urgent",
            state: "open",
            created_at,
            updated_at: created_at,
            resolved_at: None,
            closed_at: None,
        },
        300,
    )
    .await
    .unwrap();
    assert_eq!(observation.clocks_changed, 2);
    let replay = storage::observe_case_snapshot(
        &postgres,
        "acceptance-observer",
        b"case-hash-1",
        &storage::CaseSnapshot {
            observation_id: "case-observation-1-retry",
            organization_id: "org_acceptance",
            case_id: "case_opaque_1",
            source_case_revision: "case-revision-1",
            policy_id: "policy_default",
            priority: "urgent",
            state: "open",
            created_at,
            updated_at: created_at,
            resolved_at: None,
            closed_at: None,
        },
        300,
    )
    .await
    .unwrap();
    assert!(replay.replayed);

    let reconciled = storage::reconcile(
        &postgres,
        "acceptance-worker",
        "reconcile-run-1",
        b"run-hash-1",
        OffsetDateTime::now_utc(),
        100,
        300,
    )
    .await
    .unwrap();
    assert_eq!(reconciled.new_breaches, 2);
    let breaches = storage::list_breaches(
        &postgres,
        "org_acceptance",
        Some("case_opaque_1"),
        Some("pending_adapter"),
        None,
        20,
    )
    .await
    .unwrap();
    assert_eq!(breaches.breaches.len(), 2);
    assert!(
        breaches
            .breaches
            .iter()
            .all(|breach| breach.notification_status == "pending_adapter")
    );

    postgres.pool().close().await;
    sqlx::query("DROP SCHEMA IF EXISTS support_sla_acceptance CASCADE")
        .execute(&admin)
        .await
        .unwrap();
}
