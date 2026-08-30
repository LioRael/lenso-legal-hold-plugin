use lenso_postgres_kit::OwnedPostgres;
use sqlx::{AssertSqlSafe, Executor as _};
use uuid::Uuid;

use crate::{LegalHoldOperator, schema, storage};

#[tokio::test]
async fn hold_scope_blocks_retention_and_survives_restart() {
    let Ok(database_url) = std::env::var("LENSO_LEGAL_HOLD_TEST_DATABASE_URL") else {
        return;
    };
    let schema_name = format!("legal_hold_test_{}", Uuid::new_v4().simple());
    LegalHoldOperator::setup(&database_url, &schema_name)
        .await
        .unwrap();
    let postgres = OwnedPostgres::prepare(
        &database_url,
        schema::schema_plan(schema_name.clone()).unwrap(),
    )
    .await
    .unwrap();

    storage::create_hold(
        &postgres,
        storage::CreateHold {
            caller: "legal-api",
            actor: "usr_legal",
            organization_id: "org_1",
            hold_id: "hold_1",
            title: "Investigation",
            reason: "Preserve records",
            legal_authority: "court-order-1",
            idempotency_key: "create-1",
            request_hash: &[1],
        },
    )
    .await
    .unwrap();
    storage::mutate_scope(
        &postgres,
        storage::MutateScope {
            caller: "legal-api",
            actor: "usr_legal",
            operation: "add_scope",
            organization_id: "org_1",
            hold_id: "hold_1",
            scope_kind: "organization",
            scope_id: "org_1",
            subject: Some("usr_target"),
            expected_revision: 1,
            idempotency_key: "scope-1",
            request_hash: &[2],
            add: true,
        },
    )
    .await
    .unwrap();
    postgres.pool().close().await;

    let restarted = OwnedPostgres::prepare(
        &database_url,
        schema::schema_plan(schema_name.clone()).unwrap(),
    )
    .await
    .unwrap();
    let decision = storage::check_retention(
        &restarted,
        storage::RetentionCheck {
            caller: "privacy-retention",
            action_id: "action-1",
            scope_kind: "organization",
            scope_id: "org_1",
            subject: "usr_target",
            mode: "delete",
            reason: "retention elapsed",
        },
    )
    .await
    .unwrap();
    assert!(!decision.allowed);
    assert_eq!(decision.reason_code.as_deref(), Some("active_legal_hold"));

    restarted.pool().close().await;
    let cleanup = sqlx::PgPool::connect(&database_url).await.unwrap();
    cleanup
        .execute(AssertSqlSafe(format!(
            "DROP SCHEMA \"{schema_name}\" CASCADE"
        )))
        .await
        .unwrap();
    cleanup.close().await;
}
