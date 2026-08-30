use lenso_postgres_kit::OwnedPostgres;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use sqlx::{Postgres, Row, Transaction};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct HoldView {
    pub organization_id: String,
    pub hold_id: String,
    pub title: String,
    pub reason: String,
    pub legal_authority: String,
    pub status: String,
    pub revision: String,
    pub created_by: String,
    pub created_at: String,
    pub released_by: Option<String>,
    pub released_at: Option<String>,
    pub release_reason: Option<String>,
    pub scopes: Vec<ScopeView>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct ScopeView {
    pub scope_kind: String,
    pub scope_id: String,
    pub subject: Option<String>,
    pub created_at: String,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct ActivityView {
    pub activity_id: String,
    pub kind: String,
    pub actor_subject: String,
    pub payload: Value,
    pub created_at: String,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct GuardDecision {
    pub allowed: bool,
    pub decision_id: String,
    pub reason_code: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DomainFailure {
    NotFound,
    RevisionConflict,
    IdempotencyConflict,
    ScopeConflict,
    HoldReleased,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum StorageError {
    #[error("legal hold domain failure: {0:?}")]
    Domain(DomainFailure),
    #[error("PostgreSQL operation `{operation}` failed")]
    Database {
        operation: &'static str,
        #[source]
        source: sqlx::Error,
    },
    #[error("stored Legal Hold value is invalid: {0}")]
    InvalidStored(String),
    #[error("Legal Hold response serialization failed")]
    Serialization(#[from] serde_json::Error),
}

impl From<DomainFailure> for StorageError {
    fn from(value: DomainFailure) -> Self {
        Self::Domain(value)
    }
}

fn database(operation: &'static str, source: sqlx::Error) -> StorageError {
    StorageError::Database { operation, source }
}

pub(crate) struct CreateHold<'a> {
    pub caller: &'a str,
    pub actor: &'a str,
    pub organization_id: &'a str,
    pub hold_id: &'a str,
    pub title: &'a str,
    pub reason: &'a str,
    pub legal_authority: &'a str,
    pub idempotency_key: &'a str,
    pub request_hash: &'a [u8],
}

pub(crate) async fn create_hold(
    postgres: &OwnedPostgres,
    input: CreateHold<'_>,
) -> Result<HoldView, StorageError> {
    let mut transaction = postgres
        .pool()
        .begin()
        .await
        .map_err(|source| database("begin create hold", source))?;
    if let Some(response) = replay(
        &mut transaction,
        input.caller,
        input.actor,
        "create_hold",
        input.idempotency_key,
        input.request_hash,
    )
    .await?
    {
        return serde_json::from_value(response).map_err(Into::into);
    }
    let inserted = sqlx::query(
        "INSERT INTO legal_holds(hold_id,organization_id,title,reason,legal_authority,status,revision,created_by) VALUES($1,$2,$3,$4,$5,'active',1,$6) ON CONFLICT DO NOTHING",
    )
    .bind(input.hold_id)
    .bind(input.organization_id)
    .bind(input.title)
    .bind(input.reason)
    .bind(input.legal_authority)
    .bind(input.actor)
    .execute(&mut *transaction)
    .await
    .map_err(|source| database("insert legal hold", source))?
    .rows_affected();
    if inserted != 1 {
        return Err(DomainFailure::IdempotencyConflict.into());
    }
    append_activity(
        &mut transaction,
        input.organization_id,
        input.hold_id,
        "hold_created",
        input.actor,
        json!({"title": input.title, "legal_authority": input.legal_authority}),
    )
    .await?;
    let view = load_hold_tx(&mut transaction, input.organization_id, input.hold_id).await?;
    store_command(
        &mut transaction,
        input.caller,
        input.actor,
        "create_hold",
        input.idempotency_key,
        input.request_hash,
        &serde_json::to_value(&view)?,
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|source| database("commit create hold", source))?;
    Ok(view)
}

pub(crate) async fn get_hold(
    postgres: &OwnedPostgres,
    organization_id: &str,
    hold_id: &str,
) -> Result<HoldView, StorageError> {
    let mut transaction = postgres
        .pool()
        .begin()
        .await
        .map_err(|source| database("begin read hold", source))?;
    let view = load_hold_tx(&mut transaction, organization_id, hold_id).await?;
    transaction
        .commit()
        .await
        .map_err(|source| database("commit read hold", source))?;
    Ok(view)
}

pub(crate) async fn list_holds(
    postgres: &OwnedPostgres,
    organization_id: &str,
    status: Option<&str>,
    cursor: Option<&str>,
    limit: i64,
) -> Result<(Vec<HoldView>, Option<String>), StorageError> {
    let rows = sqlx::query(
        "SELECT hold_id FROM legal_holds WHERE organization_id=$1 AND ($2::text IS NULL OR status=$2) AND ($3::text IS NULL OR hold_id>$3) ORDER BY hold_id LIMIT $4",
    )
    .bind(organization_id)
    .bind(status)
    .bind(cursor)
    .bind(limit + 1)
    .fetch_all(postgres.pool())
    .await
    .map_err(|source| database("list legal holds", source))?;
    let has_more = i64::try_from(rows.len()).unwrap_or(i64::MAX) > limit;
    let mut holds = Vec::new();
    for row in rows.into_iter().take(usize::try_from(limit).unwrap_or(200)) {
        let hold_id: String = row
            .try_get("hold_id")
            .map_err(|source| database("decode listed hold", source))?;
        holds.push(get_hold(postgres, organization_id, &hold_id).await?);
    }
    let next = has_more
        .then(|| holds.last().map(|hold| hold.hold_id.clone()))
        .flatten();
    Ok((holds, next))
}

pub(crate) struct MutateScope<'a> {
    pub caller: &'a str,
    pub actor: &'a str,
    pub operation: &'static str,
    pub organization_id: &'a str,
    pub hold_id: &'a str,
    pub scope_kind: &'a str,
    pub scope_id: &'a str,
    pub subject: Option<&'a str>,
    pub expected_revision: i64,
    pub idempotency_key: &'a str,
    pub request_hash: &'a [u8],
    pub add: bool,
}

pub(crate) async fn mutate_scope(
    postgres: &OwnedPostgres,
    input: MutateScope<'_>,
) -> Result<HoldView, StorageError> {
    let mut transaction = postgres
        .pool()
        .begin()
        .await
        .map_err(|source| database("begin mutate hold scope", source))?;
    if let Some(response) = replay(
        &mut transaction,
        input.caller,
        input.actor,
        input.operation,
        input.idempotency_key,
        input.request_hash,
    )
    .await?
    {
        return serde_json::from_value(response).map_err(Into::into);
    }
    let (status, revision) =
        lock_hold(&mut transaction, input.organization_id, input.hold_id).await?;
    if status != "active" {
        return Err(DomainFailure::HoldReleased.into());
    }
    if revision != input.expected_revision {
        return Err(DomainFailure::RevisionConflict.into());
    }
    let changed = if input.add {
        sqlx::query("INSERT INTO legal_hold_scopes(hold_id,scope_kind,scope_id,subject,created_by) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING")
            .bind(input.hold_id)
            .bind(input.scope_kind)
            .bind(input.scope_id)
            .bind(input.subject)
            .bind(input.actor)
            .execute(&mut *transaction)
            .await
            .map_err(|source| database("add legal hold scope", source))?
            .rows_affected()
    } else {
        sqlx::query("DELETE FROM legal_hold_scopes WHERE hold_id=$1 AND scope_kind=$2 AND scope_id=$3 AND subject IS NOT DISTINCT FROM $4")
            .bind(input.hold_id)
            .bind(input.scope_kind)
            .bind(input.scope_id)
            .bind(input.subject)
            .execute(&mut *transaction)
            .await
            .map_err(|source| database("remove legal hold scope", source))?
            .rows_affected()
    };
    if changed != 1 {
        return Err(DomainFailure::ScopeConflict.into());
    }
    sqlx::query("UPDATE legal_holds SET revision=revision+1 WHERE hold_id=$1")
        .bind(input.hold_id)
        .execute(&mut *transaction)
        .await
        .map_err(|source| database("advance legal hold revision", source))?;
    append_activity(
        &mut transaction,
        input.organization_id,
        input.hold_id,
        if input.add {
            "scope_added"
        } else {
            "scope_removed"
        },
        input.actor,
        json!({"scope_kind":input.scope_kind,"scope_id":input.scope_id,"subject":input.subject}),
    )
    .await?;
    let view = load_hold_tx(&mut transaction, input.organization_id, input.hold_id).await?;
    store_command(
        &mut transaction,
        input.caller,
        input.actor,
        input.operation,
        input.idempotency_key,
        input.request_hash,
        &serde_json::to_value(&view)?,
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|source| database("commit mutate hold scope", source))?;
    Ok(view)
}

pub(crate) struct ReleaseHold<'a> {
    pub caller: &'a str,
    pub actor: &'a str,
    pub organization_id: &'a str,
    pub hold_id: &'a str,
    pub expected_revision: i64,
    pub reason: &'a str,
    pub idempotency_key: &'a str,
    pub request_hash: &'a [u8],
}

pub(crate) async fn release_hold(
    postgres: &OwnedPostgres,
    input: ReleaseHold<'_>,
) -> Result<HoldView, StorageError> {
    let mut transaction = postgres
        .pool()
        .begin()
        .await
        .map_err(|source| database("begin release hold", source))?;
    if let Some(response) = replay(
        &mut transaction,
        input.caller,
        input.actor,
        "release_hold",
        input.idempotency_key,
        input.request_hash,
    )
    .await?
    {
        return serde_json::from_value(response).map_err(Into::into);
    }
    let (status, revision) =
        lock_hold(&mut transaction, input.organization_id, input.hold_id).await?;
    if status != "active" {
        return Err(DomainFailure::HoldReleased.into());
    }
    if revision != input.expected_revision {
        return Err(DomainFailure::RevisionConflict.into());
    }
    sqlx::query("UPDATE legal_holds SET status='released',revision=revision+1,released_by=$2,released_at=transaction_timestamp(),release_reason=$3 WHERE hold_id=$1")
        .bind(input.hold_id)
        .bind(input.actor)
        .bind(input.reason)
        .execute(&mut *transaction)
        .await
        .map_err(|source| database("release legal hold", source))?;
    append_activity(
        &mut transaction,
        input.organization_id,
        input.hold_id,
        "hold_released",
        input.actor,
        json!({"reason": input.reason}),
    )
    .await?;
    let view = load_hold_tx(&mut transaction, input.organization_id, input.hold_id).await?;
    store_command(
        &mut transaction,
        input.caller,
        input.actor,
        "release_hold",
        input.idempotency_key,
        input.request_hash,
        &serde_json::to_value(&view)?,
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|source| database("commit release hold", source))?;
    Ok(view)
}

pub(crate) async fn list_activity(
    postgres: &OwnedPostgres,
    organization_id: &str,
    hold_id: &str,
    after: i64,
    limit: i64,
) -> Result<(Vec<ActivityView>, i64), StorageError> {
    get_hold(postgres, organization_id, hold_id).await?;
    let rows = sqlx::query("SELECT activity_id,kind,actor_subject,payload,created_at FROM legal_hold_activity WHERE organization_id=$1 AND hold_id=$2 AND activity_id>$3 ORDER BY activity_id LIMIT $4")
        .bind(organization_id)
        .bind(hold_id)
        .bind(after)
        .bind(limit)
        .fetch_all(postgres.pool())
        .await
        .map_err(|source| database("list legal hold activity", source))?;
    let mut events = Vec::with_capacity(rows.len());
    for row in rows {
        let activity_id: i64 = row
            .try_get("activity_id")
            .map_err(|source| database("decode activity id", source))?;
        events.push(ActivityView {
            activity_id: activity_id.to_string(),
            kind: row
                .try_get("kind")
                .map_err(|source| database("decode activity kind", source))?,
            actor_subject: row
                .try_get("actor_subject")
                .map_err(|source| database("decode activity actor", source))?,
            payload: row
                .try_get("payload")
                .map_err(|source| database("decode activity payload", source))?,
            created_at: format_time(
                row.try_get("created_at")
                    .map_err(|source| database("decode activity time", source))?,
            )?,
        });
    }
    let next = events
        .last()
        .map_or(after, |event| event.activity_id.parse().unwrap_or(after));
    Ok((events, next))
}

pub(crate) struct RetentionCheck<'a> {
    pub caller: &'a str,
    pub action_id: &'a str,
    pub scope_kind: &'a str,
    pub scope_id: &'a str,
    pub subject: &'a str,
    pub mode: &'a str,
    pub reason: &'a str,
}

pub(crate) async fn check_retention(
    postgres: &OwnedPostgres,
    input: RetentionCheck<'_>,
) -> Result<GuardDecision, StorageError> {
    let rows = sqlx::query("SELECT h.hold_id,h.revision FROM legal_holds h JOIN legal_hold_scopes s ON s.hold_id=h.hold_id WHERE h.status='active' AND s.scope_kind=$1 AND s.scope_id=$2 AND (s.subject IS NULL OR s.subject=$3) ORDER BY h.hold_id")
        .bind(input.scope_kind)
        .bind(input.scope_id)
        .bind(input.subject)
        .fetch_all(postgres.pool())
        .await
        .map_err(|source| database("evaluate legal hold guard", source))?;
    let matching_holds = rows
        .into_iter()
        .map(|row| -> Result<Value, StorageError> {
            let hold_id: String = row
                .try_get("hold_id")
                .map_err(|source| database("decode matching hold", source))?;
            let revision: i64 = row
                .try_get("revision")
                .map_err(|source| database("decode matching revision", source))?;
            Ok(json!({"hold_id":hold_id,"revision":revision.to_string()}))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let evidence = json!({
        "caller":input.caller,"action_id":input.action_id,"scope_kind":input.scope_kind,
        "scope_id":input.scope_id,"subject":input.subject,"mode":input.mode,
        "reason":input.reason,"matching_holds":matching_holds
    });
    let request_hash = Sha256::digest(serde_json::to_vec(&evidence)?);
    let decision_id = format!("guard:{}", hex::encode(request_hash));
    let allowed = matching_holds.is_empty();
    let reason_code = (!allowed).then(|| "active_legal_hold".to_owned());
    sqlx::query("INSERT INTO legal_hold_guard_decisions(decision_id,action_id,caller_instance,request_hash,allowed,reason_code,matching_holds) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(decision_id) DO NOTHING")
        .bind(&decision_id)
        .bind(input.action_id)
        .bind(input.caller)
        .bind(&request_hash[..])
        .bind(allowed)
        .bind(&reason_code)
        .bind(json!(matching_holds))
        .execute(postgres.pool())
        .await
        .map_err(|source| database("store legal hold guard decision", source))?;
    Ok(GuardDecision {
        allowed,
        decision_id,
        reason_code,
    })
}

async fn lock_hold(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    hold_id: &str,
) -> Result<(String, i64), StorageError> {
    let row = sqlx::query("SELECT status,revision FROM legal_holds WHERE organization_id=$1 AND hold_id=$2 FOR UPDATE")
        .bind(organization_id)
        .bind(hold_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|source| database("lock legal hold", source))?
        .ok_or(DomainFailure::NotFound)?;
    Ok((
        row.try_get("status")
            .map_err(|source| database("decode hold status", source))?,
        row.try_get("revision")
            .map_err(|source| database("decode hold revision", source))?,
    ))
}

async fn load_hold_tx(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    hold_id: &str,
) -> Result<HoldView, StorageError> {
    let row = sqlx::query("SELECT organization_id,hold_id,title,reason,legal_authority,status,revision,created_by,created_at,released_by,released_at,release_reason FROM legal_holds WHERE organization_id=$1 AND hold_id=$2")
        .bind(organization_id)
        .bind(hold_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|source| database("read legal hold", source))?
        .ok_or(DomainFailure::NotFound)?;
    let scope_rows = sqlx::query("SELECT scope_kind,scope_id,subject,created_at FROM legal_hold_scopes WHERE hold_id=$1 ORDER BY scope_kind,scope_id,subject NULLS FIRST")
        .bind(hold_id)
        .fetch_all(&mut **transaction)
        .await
        .map_err(|source| database("read legal hold scopes", source))?;
    let mut scopes = Vec::with_capacity(scope_rows.len());
    for scope in scope_rows {
        scopes.push(ScopeView {
            scope_kind: scope
                .try_get("scope_kind")
                .map_err(|source| database("decode scope kind", source))?,
            scope_id: scope
                .try_get("scope_id")
                .map_err(|source| database("decode scope id", source))?,
            subject: scope
                .try_get("subject")
                .map_err(|source| database("decode scope subject", source))?,
            created_at: format_time(
                scope
                    .try_get("created_at")
                    .map_err(|source| database("decode scope time", source))?,
            )?,
        });
    }
    let released_at: Option<OffsetDateTime> = row
        .try_get("released_at")
        .map_err(|source| database("decode release time", source))?;
    Ok(HoldView {
        organization_id: row
            .try_get("organization_id")
            .map_err(|source| database("decode organization", source))?,
        hold_id: row
            .try_get("hold_id")
            .map_err(|source| database("decode hold id", source))?,
        title: row
            .try_get("title")
            .map_err(|source| database("decode title", source))?,
        reason: row
            .try_get("reason")
            .map_err(|source| database("decode reason", source))?,
        legal_authority: row
            .try_get("legal_authority")
            .map_err(|source| database("decode authority", source))?,
        status: row
            .try_get("status")
            .map_err(|source| database("decode status", source))?,
        revision: row
            .try_get::<i64, _>("revision")
            .map_err(|source| database("decode revision", source))?
            .to_string(),
        created_by: row
            .try_get("created_by")
            .map_err(|source| database("decode creator", source))?,
        created_at: format_time(
            row.try_get("created_at")
                .map_err(|source| database("decode creation time", source))?,
        )?,
        released_by: row
            .try_get("released_by")
            .map_err(|source| database("decode releaser", source))?,
        released_at: released_at.map(format_time).transpose()?,
        release_reason: row
            .try_get("release_reason")
            .map_err(|source| database("decode release reason", source))?,
        scopes,
    })
}

async fn append_activity(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    hold_id: &str,
    kind: &str,
    actor: &str,
    payload: Value,
) -> Result<(), StorageError> {
    sqlx::query("INSERT INTO legal_hold_activity(organization_id,hold_id,kind,actor_subject,payload) VALUES($1,$2,$3,$4,$5)")
        .bind(organization_id).bind(hold_id).bind(kind).bind(actor).bind(payload)
        .execute(&mut **transaction).await
        .map_err(|source| database("append legal hold activity", source))?;
    Ok(())
}

async fn replay(
    transaction: &mut Transaction<'_, Postgres>,
    caller: &str,
    actor: &str,
    operation: &str,
    idempotency_key: &str,
    request_hash: &[u8],
) -> Result<Option<Value>, StorageError> {
    let row = sqlx::query("SELECT request_hash,response FROM legal_hold_commands WHERE caller_instance=$1 AND actor_subject=$2 AND operation=$3 AND idempotency_key=$4")
        .bind(caller).bind(actor).bind(operation).bind(idempotency_key)
        .fetch_optional(&mut **transaction).await
        .map_err(|source| database("read legal hold command", source))?;
    let Some(row) = row else {
        return Ok(None);
    };
    let stored_hash: Vec<u8> = row
        .try_get("request_hash")
        .map_err(|source| database("decode command hash", source))?;
    if stored_hash != request_hash {
        return Err(DomainFailure::IdempotencyConflict.into());
    }
    row.try_get("response")
        .map(Some)
        .map_err(|source| database("decode command response", source))
}

async fn store_command(
    transaction: &mut Transaction<'_, Postgres>,
    caller: &str,
    actor: &str,
    operation: &str,
    idempotency_key: &str,
    request_hash: &[u8],
    response: &Value,
) -> Result<(), StorageError> {
    sqlx::query("INSERT INTO legal_hold_commands(caller_instance,actor_subject,operation,idempotency_key,request_hash,response) VALUES($1,$2,$3,$4,$5,$6)")
        .bind(caller).bind(actor).bind(operation).bind(idempotency_key).bind(request_hash).bind(response)
        .execute(&mut **transaction).await
        .map_err(|source| database("store legal hold command", source))?;
    Ok(())
}

fn format_time(value: OffsetDateTime) -> Result<String, StorageError> {
    value
        .format(&Rfc3339)
        .map_err(|error| StorageError::InvalidStored(error.to_string()))
}
