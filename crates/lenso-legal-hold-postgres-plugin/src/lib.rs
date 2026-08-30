//! PostgreSQL-backed Legal Hold Plugin and fail-closed Retention Guard.

mod operator;
#[cfg(all(test, feature = "postgres-acceptance"))]
mod postgres_tests;
mod schema;
mod storage;

use std::{cell::RefCell, collections::BTreeSet, fmt, rc::Rc, time::Duration};

use lenso::prelude::*;
use lenso_auth_sdk::{
    ActorAssertion, ActorAssertionVerifier, ActorProjectionError, AssertionClock, TypedActor,
};
use lenso_capability_access_control as access;
use lenso_capability_access_control::{
    AccessControlInvocationError, CheckPermissionRequest, CheckPermissionRequestScope,
};
use lenso_capability_legal_hold as legal;
use lenso_capability_legal_hold::{
    AddScopeError, AddScopeRequest, AddScopeResponse, CreateHoldError, CreateHoldRequest,
    CreateHoldResponse, GetHoldError, GetHoldRequest, GetHoldResponse, ListActivityError,
    ListActivityRequest, ListActivityResponse, ListHoldsError, ListHoldsRequest,
    ListHoldsRequestStatus, ListHoldsResponse, ReleaseHoldError, ReleaseHoldRequest,
    ReleaseHoldResponse, RemoveScopeError, RemoveScopeRequest, RemoveScopeResponse,
};
use lenso_capability_organization_membership as membership;
use lenso_capability_organization_membership::{
    CheckMembershipRequest, OrganizationMembershipInvocationError,
};
use lenso_capability_retention_guard as guard;
use lenso_capability_retention_guard::{
    CheckRetentionError, CheckRetentionRequest, CheckRetentionRequestMode, CheckRetentionResponse,
};
use lenso_capability_secrets as secrets;
use lenso_capability_secrets::{ResolveRequest, SecretsClient, SecretsInvocationError};
use lenso_kernel::{PluginDependencies, RuntimeFailure};
use lenso_postgres_kit::OwnedPostgres;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use time::OffsetDateTime;
use zeroize::Zeroizing;

use crate::storage::{DomainFailure, StorageError};

pub use operator::{LegalHoldOperator, LegalHoldOperatorError};

const DEPENDENCY_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_CALLERS: usize = 64;
const MAX_ID_BYTES: usize = 512;
const MAX_SHORT_TEXT_BYTES: usize = 1_000;
const MAX_REASON_BYTES: usize = 20_000;
const MAX_IDEMPOTENCY_BYTES: usize = 200;
const MAX_PAGE_SIZE: i64 = 200;

const LEGAL_HOLD_READ: &str = "legal-hold.read";
const LEGAL_HOLD_WRITE: &str = "legal-hold.write";
const LEGAL_HOLD_RELEASE: &str = "legal-hold.release";

/// Immutable configuration for one Legal Hold Plugin Instance.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LegalHoldConfig {
    schema: String,
    database_url_secret: String,
    auth_issuer: String,
    auth_assertion_public_key: String,
    admin_callers: Vec<String>,
    guard_callers: Vec<String>,
}

impl LegalHoldConfig {
    /// Creates and validates Legal Hold configuration.
    pub fn new(
        schema: impl Into<String>,
        database_url_secret: impl Into<String>,
        auth_issuer: impl Into<String>,
        auth_assertion_public_key: impl Into<String>,
        admin_callers: Vec<String>,
        guard_callers: Vec<String>,
    ) -> Result<Self, LegalHoldConfigError> {
        let config = Self {
            schema: schema.into(),
            database_url_secret: database_url_secret.into(),
            auth_issuer: auth_issuer.into(),
            auth_assertion_public_key: auth_assertion_public_key.into(),
            admin_callers,
            guard_callers,
        };
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), LegalHoldConfigError> {
        schema::schema_plan(self.schema.clone())
            .map_err(|_| LegalHoldConfigError::InvalidSchema)?;
        if !valid_identifier(&self.database_url_secret, 256) {
            return Err(LegalHoldConfigError::InvalidSecretReference);
        }
        if !valid_identifier(&self.auth_issuer, 256) {
            return Err(LegalHoldConfigError::InvalidAuthIssuer);
        }
        ActorAssertionVerifier::from_public_key_base64(
            self.auth_issuer.clone(),
            &self.auth_assertion_public_key,
        )
        .map_err(|_| LegalHoldConfigError::InvalidAuthPublicKey)?;
        validate_callers(&self.admin_callers)
            .map_err(|()| LegalHoldConfigError::InvalidAdminCallers)?;
        validate_callers(&self.guard_callers)
            .map_err(|()| LegalHoldConfigError::InvalidGuardCallers)?;
        Ok(())
    }

    fn verifier(&self) -> Result<ActorAssertionVerifier, RuntimeFailure> {
        ActorAssertionVerifier::from_public_key_base64(
            self.auth_issuer.clone(),
            &self.auth_assertion_public_key,
        )
        .map_err(|_| RuntimeFailure::InvalidResolvedPlan {
            detail: "Legal Hold Auth verification key is invalid".to_owned(),
        })
    }
}

/// Invalid immutable Legal Hold configuration.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum LegalHoldConfigError {
    #[error("invalid owned PostgreSQL schema")]
    InvalidSchema,
    #[error("invalid database URL secret reference")]
    InvalidSecretReference,
    #[error("invalid Auth issuer")]
    InvalidAuthIssuer,
    #[error("invalid Auth assertion public key")]
    InvalidAuthPublicKey,
    #[error("admin_callers must contain unique exact Instance keys")]
    InvalidAdminCallers,
    #[error("guard_callers must contain unique exact Instance keys")]
    InvalidGuardCallers,
}

fn validate_config(config: &LegalHoldConfig) -> Result<(), RuntimeFailure> {
    config
        .validate()
        .map_err(|error| RuntimeFailure::InvalidResolvedPlan {
            detail: format!("Legal Hold configuration is invalid: {error}"),
        })
}

#[derive(Clone, Debug)]
struct PreparedLegalHold {
    postgres: OwnedPostgres,
}

#[lenso::plugin(
    lifecycle,
    configuration_schema = "configuration.schema.json",
    validate = validate_config
)]
#[derive(Clone)]
struct PostgresLegalHoldPlugin {
    #[config]
    config: LegalHoldConfig,
    secrets: Port<secrets::SecretsClient>,
    membership: Port<membership::OrganizationMembershipClient>,
    access: Port<access::AccessControlClient>,
    prepared: Rc<RefCell<Option<PreparedLegalHold>>>,
}

impl fmt::Debug for PostgresLegalHoldPlugin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgresLegalHoldPlugin")
            .field("schema", &self.config.schema)
            .field("prepared", &self.prepared.borrow().is_some())
            .field("admin_caller_count", &self.config.admin_callers.len())
            .field("guard_caller_count", &self.config.guard_callers.len())
            .finish_non_exhaustive()
    }
}

#[lenso::provides(legal::LegalHold, guard::RetentionGuard)]
impl PostgresLegalHoldPlugin {}

impl PostgresLegalHoldPlugin {
    async fn create_hold(
        &self,
        context: Ctx,
        request: CreateHoldRequest,
    ) -> PluginResult<CreateHoldResponse, CreateHoldError> {
        let (caller, actor) = self
            .authorize_admin(
                &context,
                legal::CREATE_HOLD_OPERATION,
                &request.organization_id,
                LEGAL_HOLD_WRITE,
            )
            .await
            .map_err(map_create_authorization)?;
        if !valid_id(&request.organization_id)
            || !valid_id(&request.hold_id)
            || !valid_text(&request.title, MAX_SHORT_TEXT_BYTES, false)
            || !valid_text(&request.reason, MAX_REASON_BYTES, false)
            || !valid_text(&request.legal_authority, MAX_SHORT_TEXT_BYTES, false)
            || !valid_idempotency_key(&request.idempotency_key)
        {
            return Err(PluginError::domain(CreateHoldError::InvalidRequest));
        }
        let request_hash = request_hash(&request)?;
        let result = storage::create_hold(
            &self.prepared().map_err(PluginError::runtime)?.postgres,
            storage::CreateHold {
                caller: &caller,
                actor: &actor,
                organization_id: &request.organization_id,
                hold_id: &request.hold_id,
                title: &request.title,
                reason: &request.reason,
                legal_authority: &request.legal_authority,
                idempotency_key: &request.idempotency_key,
                request_hash: &request_hash,
            },
        )
        .await;
        wire_cast(&map_storage(result, map_create_domain)?)
    }

    async fn get_hold(
        &self,
        context: Ctx,
        request: GetHoldRequest,
    ) -> PluginResult<GetHoldResponse, GetHoldError> {
        self.authorize_admin(
            &context,
            legal::GET_HOLD_OPERATION,
            &request.organization_id,
            LEGAL_HOLD_READ,
        )
        .await
        .map_err(map_get_authorization)?;
        if !valid_id(&request.organization_id) || !valid_id(&request.hold_id) {
            return Err(PluginError::domain(GetHoldError::InvalidRequest));
        }
        let result = storage::get_hold(
            &self.prepared().map_err(PluginError::runtime)?.postgres,
            &request.organization_id,
            &request.hold_id,
        )
        .await;
        wire_cast(&map_storage(result, map_get_domain)?)
    }

    async fn list_holds(
        &self,
        context: Ctx,
        request: ListHoldsRequest,
    ) -> PluginResult<ListHoldsResponse, ListHoldsError> {
        self.authorize_admin(
            &context,
            legal::LIST_HOLDS_OPERATION,
            &request.organization_id,
            LEGAL_HOLD_READ,
        )
        .await
        .map_err(map_list_holds_authorization)?;
        if !valid_id(&request.organization_id)
            || !(1..=MAX_PAGE_SIZE).contains(&request.limit)
            || request
                .cursor
                .as_deref()
                .is_some_and(|value| !valid_id(value))
        {
            return Err(PluginError::domain(ListHoldsError::InvalidRequest));
        }
        let status = request.status.as_ref().map(|value| match value {
            ListHoldsRequestStatus::Active => "active",
            ListHoldsRequestStatus::Released => "released",
        });
        let result = storage::list_holds(
            &self.prepared().map_err(PluginError::runtime)?.postgres,
            &request.organization_id,
            status,
            request.cursor.as_deref(),
            request.limit,
        )
        .await;
        let (holds, next_cursor) = map_storage(result, map_list_holds_domain)?;
        Ok(ListHoldsResponse {
            holds: wire_cast(&holds)?,
            next_cursor,
        })
    }

    async fn add_scope(
        &self,
        context: Ctx,
        request: AddScopeRequest,
    ) -> PluginResult<AddScopeResponse, AddScopeError> {
        let (caller, actor) = self
            .authorize_admin(
                &context,
                legal::ADD_SCOPE_OPERATION,
                &request.organization_id,
                LEGAL_HOLD_WRITE,
            )
            .await
            .map_err(map_add_scope_authorization)?;
        self.mutate_scope(
            request.organization_id,
            request.hold_id,
            request.scope_kind,
            request.scope_id,
            request.subject.flatten(),
            request.expected_revision,
            request.idempotency_key,
            caller,
            actor,
            legal::ADD_SCOPE_OPERATION,
            true,
            || AddScopeError::InvalidRequest,
            map_add_scope_domain,
        )
        .await
    }

    async fn remove_scope(
        &self,
        context: Ctx,
        request: RemoveScopeRequest,
    ) -> PluginResult<RemoveScopeResponse, RemoveScopeError> {
        let (caller, actor) = self
            .authorize_admin(
                &context,
                legal::REMOVE_SCOPE_OPERATION,
                &request.organization_id,
                LEGAL_HOLD_WRITE,
            )
            .await
            .map_err(map_remove_scope_authorization)?;
        self.mutate_scope(
            request.organization_id,
            request.hold_id,
            request.scope_kind,
            request.scope_id,
            request.subject.flatten(),
            request.expected_revision,
            request.idempotency_key,
            caller,
            actor,
            legal::REMOVE_SCOPE_OPERATION,
            false,
            || RemoveScopeError::InvalidRequest,
            map_remove_scope_domain,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn mutate_scope<T, E>(
        &self,
        organization_id: String,
        hold_id: String,
        scope_kind: String,
        scope_id: String,
        subject: Option<String>,
        expected_revision: String,
        idempotency_key: String,
        caller: String,
        actor: String,
        operation: &'static str,
        add: bool,
        invalid_error: fn() -> E,
        map_domain: fn(DomainFailure) -> E,
    ) -> PluginResult<T, E>
    where
        T: DeserializeOwned,
    {
        let Some(expected_revision) = parse_revision(&expected_revision) else {
            return Err(PluginError::domain(invalid_error()));
        };
        if !valid_id(&organization_id)
            || !valid_id(&hold_id)
            || !valid_text(&scope_kind, 128, false)
            || !valid_id(&scope_id)
            || subject.as_deref().is_some_and(|value| !valid_id(value))
            || !valid_idempotency_key(&idempotency_key)
        {
            return Err(PluginError::domain(invalid_error()));
        }
        let hash_input = serde_json::json!({
            "organization_id": organization_id,
            "hold_id": hold_id,
            "scope_kind": scope_kind,
            "scope_id": scope_id,
            "subject": subject,
            "expected_revision": expected_revision.to_string(),
            "idempotency_key": idempotency_key,
        });
        let request_hash = request_hash(&hash_input)?;
        let result = storage::mutate_scope(
            &self.prepared().map_err(PluginError::runtime)?.postgres,
            storage::MutateScope {
                caller: &caller,
                actor: &actor,
                operation,
                organization_id: hash_input["organization_id"].as_str().unwrap_or_default(),
                hold_id: hash_input["hold_id"].as_str().unwrap_or_default(),
                scope_kind: hash_input["scope_kind"].as_str().unwrap_or_default(),
                scope_id: hash_input["scope_id"].as_str().unwrap_or_default(),
                subject: hash_input["subject"].as_str(),
                expected_revision,
                idempotency_key: hash_input["idempotency_key"].as_str().unwrap_or_default(),
                request_hash: &request_hash,
                add,
            },
        )
        .await;
        wire_cast(&map_storage(result, map_domain)?)
    }

    async fn release_hold(
        &self,
        context: Ctx,
        request: ReleaseHoldRequest,
    ) -> PluginResult<ReleaseHoldResponse, ReleaseHoldError> {
        let (caller, actor) = self
            .authorize_admin(
                &context,
                legal::RELEASE_HOLD_OPERATION,
                &request.organization_id,
                LEGAL_HOLD_RELEASE,
            )
            .await
            .map_err(map_release_authorization)?;
        let Some(expected_revision) = parse_revision(&request.expected_revision) else {
            return Err(PluginError::domain(ReleaseHoldError::InvalidRequest));
        };
        if !valid_id(&request.organization_id)
            || !valid_id(&request.hold_id)
            || !valid_text(&request.reason, MAX_REASON_BYTES, false)
            || !valid_idempotency_key(&request.idempotency_key)
        {
            return Err(PluginError::domain(ReleaseHoldError::InvalidRequest));
        }
        let request_hash = request_hash(&request)?;
        let result = storage::release_hold(
            &self.prepared().map_err(PluginError::runtime)?.postgres,
            storage::ReleaseHold {
                caller: &caller,
                actor: &actor,
                organization_id: &request.organization_id,
                hold_id: &request.hold_id,
                expected_revision,
                reason: &request.reason,
                idempotency_key: &request.idempotency_key,
                request_hash: &request_hash,
            },
        )
        .await;
        wire_cast(&map_storage(result, map_release_domain)?)
    }

    async fn list_activity(
        &self,
        context: Ctx,
        request: ListActivityRequest,
    ) -> PluginResult<ListActivityResponse, ListActivityError> {
        self.authorize_admin(
            &context,
            legal::LIST_ACTIVITY_OPERATION,
            &request.organization_id,
            LEGAL_HOLD_READ,
        )
        .await
        .map_err(map_list_activity_authorization)?;
        let after = request
            .after
            .as_deref()
            .unwrap_or("0")
            .parse::<i64>()
            .ok()
            .filter(|value| *value >= 0);
        if !valid_id(&request.organization_id)
            || !valid_id(&request.hold_id)
            || !(1..=MAX_PAGE_SIZE).contains(&request.limit)
            || after.is_none()
        {
            return Err(PluginError::domain(ListActivityError::InvalidRequest));
        }
        let result = storage::list_activity(
            &self.prepared().map_err(PluginError::runtime)?.postgres,
            &request.organization_id,
            &request.hold_id,
            after.unwrap_or_default(),
            request.limit,
        )
        .await;
        let (events, next_cursor) = map_storage(result, map_list_activity_domain)?;
        Ok(ListActivityResponse {
            events: wire_cast(&events)?,
            next_cursor: next_cursor.to_string(),
        })
    }

    async fn check_retention(
        &self,
        context: Ctx,
        request: CheckRetentionRequest,
    ) -> PluginResult<CheckRetentionResponse, CheckRetentionError> {
        let caller = Self::allowed_caller(&context, &self.config.guard_callers)
            .ok_or_else(|| PluginError::domain(CheckRetentionError::Forbidden))?;
        if !valid_id(&request.action_id)
            || !valid_text(&request.scope_kind, 128, false)
            || !valid_id(&request.scope_id)
            || !valid_id(&request.subject)
            || !valid_text(&request.reason, MAX_REASON_BYTES, true)
        {
            return Err(PluginError::domain(CheckRetentionError::InvalidRequest));
        }
        let mode = match request.mode {
            CheckRetentionRequestMode::Delete => "delete",
            CheckRetentionRequestMode::Anonymize => "anonymize",
        };
        let decision = storage::check_retention(
            &self.prepared().map_err(PluginError::runtime)?.postgres,
            storage::RetentionCheck {
                caller: &caller,
                action_id: &request.action_id,
                scope_kind: &request.scope_kind,
                scope_id: &request.scope_id,
                subject: &request.subject,
                mode,
                reason: &request.reason,
            },
        )
        .await
        .map_err(storage_runtime)?;
        Ok(CheckRetentionResponse {
            allowed: decision.allowed,
            decision_id: decision.decision_id,
            reason_code: decision.reason_code.map(Some),
        })
    }

    fn prepared(&self) -> Result<PreparedLegalHold, RuntimeFailure> {
        self.prepared
            .borrow()
            .clone()
            .ok_or_else(|| RuntimeFailure::PluginFailure {
                detail: "Legal Hold Plugin is not prepared".to_owned(),
            })
    }

    async fn authorize_admin(
        &self,
        context: &Ctx,
        operation: &str,
        organization_id: &str,
        permission: &str,
    ) -> Result<(String, String), AuthorizationFailure> {
        let caller = Self::allowed_caller(context, &self.config.admin_callers)
            .ok_or(AuthorizationFailure::Forbidden)?;
        let actor = self
            .authenticated_subject(context, operation)
            .map_err(|()| AuthorizationFailure::Unauthenticated)?;
        if !self
            .membership
            .check_membership_with_context(
                context.clone(),
                CheckMembershipRequest {
                    organization_id: organization_id.to_owned(),
                    subject: actor.clone(),
                },
            )
            .await
            .map(|response| response.active)
            .map_err(|error| match error {
                OrganizationMembershipInvocationError::Domain(_) => RuntimeFailure::PluginFailure {
                    detail: "Organization Membership rejected a Legal Hold authorization query"
                        .to_owned(),
                },
                OrganizationMembershipInvocationError::Runtime(error) => error,
            })
            .map_err(AuthorizationFailure::Runtime)?
        {
            return Err(AuthorizationFailure::Forbidden);
        }
        if !self
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
            .map(|response| response.allowed)
            .map_err(|error| match error {
                AccessControlInvocationError::Domain(_) => RuntimeFailure::PluginFailure {
                    detail: "Access Control rejected a Legal Hold authorization query".to_owned(),
                },
                AccessControlInvocationError::Runtime(error) => error,
            })
            .map_err(AuthorizationFailure::Runtime)?
        {
            return Err(AuthorizationFailure::Forbidden);
        }
        Ok((caller, actor))
    }

    fn allowed_caller(context: &Ctx, allowed: &[String]) -> Option<String> {
        context.caller_instance().and_then(|caller| {
            allowed
                .iter()
                .any(|entry| entry == caller)
                .then(|| caller.to_owned())
        })
    }

    fn authenticated_subject(&self, context: &Ctx, operation: &str) -> Result<String, ()> {
        let actor = self
            .config
            .verifier()
            .map_err(|_| ())?
            .project_context::<LegalHoldActor>(context, legal::CAPABILITY_ID, operation, &UtcClock)
            .map_err(|_| ())?;
        valid_id(&actor.subject).then_some(actor.subject).ok_or(())
    }
}

impl Lifecycle for PostgresLegalHoldPlugin {
    async fn activate(&self, context: ActivateContext) -> Result<(), RuntimeFailure> {
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
            .replace(PreparedLegalHold { postgres });
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

#[derive(Clone, Debug)]
struct LegalHoldActor {
    subject: String,
}

impl TypedActor for LegalHoldActor {
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

#[derive(Debug)]
enum AuthorizationFailure {
    Unauthenticated,
    Forbidden,
    Runtime(RuntimeFailure),
}

async fn resolve_secret(
    secrets: &SecretsClient,
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
        .map(|response| Zeroizing::new(response.value))
        .map_err(|error| match error {
            SecretsInvocationError::Domain(_) => RuntimeFailure::PluginFailure {
                detail: format!("database URL secret `{reference}` was rejected"),
            },
            SecretsInvocationError::Runtime(error) => error,
        })
}

fn map_storage<T, E>(
    result: Result<T, StorageError>,
    map_domain: fn(DomainFailure) -> E,
) -> PluginResult<T, E> {
    match result {
        Ok(value) => Ok(value),
        Err(StorageError::Domain(failure)) => Err(PluginError::domain(map_domain(failure))),
        Err(error) => Err(storage_runtime(error)),
    }
}

fn map_create_domain(failure: DomainFailure) -> CreateHoldError {
    match failure {
        DomainFailure::IdempotencyConflict => CreateHoldError::IdempotencyConflict,
        _ => CreateHoldError::InvalidRequest,
    }
}

macro_rules! map_common_domain {
    ($name:ident, $error:ty) => {
        fn $name(failure: DomainFailure) -> $error {
            match failure {
                DomainFailure::NotFound => <$error>::NotFound,
                DomainFailure::RevisionConflict => <$error>::RevisionConflict,
                DomainFailure::IdempotencyConflict => <$error>::IdempotencyConflict,
                DomainFailure::ScopeConflict => <$error>::ScopeConflict,
                DomainFailure::HoldReleased => <$error>::HoldReleased,
            }
        }
    };
}

map_common_domain!(map_get_domain, GetHoldError);
map_common_domain!(map_list_holds_domain, ListHoldsError);
map_common_domain!(map_add_scope_domain, AddScopeError);
map_common_domain!(map_remove_scope_domain, RemoveScopeError);
map_common_domain!(map_release_domain, ReleaseHoldError);
map_common_domain!(map_list_activity_domain, ListActivityError);

macro_rules! map_authorization {
    ($name:ident, $error:ty) => {
        fn $name(failure: AuthorizationFailure) -> PluginError<$error> {
            match failure {
                AuthorizationFailure::Unauthenticated => {
                    PluginError::domain(<$error>::Unauthenticated)
                }
                AuthorizationFailure::Forbidden => PluginError::domain(<$error>::Forbidden),
                AuthorizationFailure::Runtime(error) => PluginError::runtime(error),
            }
        }
    };
}

map_authorization!(map_create_authorization, CreateHoldError);
map_authorization!(map_get_authorization, GetHoldError);
map_authorization!(map_list_holds_authorization, ListHoldsError);
map_authorization!(map_add_scope_authorization, AddScopeError);
map_authorization!(map_remove_scope_authorization, RemoveScopeError);
map_authorization!(map_release_authorization, ReleaseHoldError);
map_authorization!(map_list_activity_authorization, ListActivityError);

fn request_hash<T: Serialize, E>(request: &T) -> Result<Vec<u8>, PluginError<E>> {
    serde_json::to_vec(request)
        .map(|wire| Sha256::digest(wire).to_vec())
        .map_err(serialization_runtime)
}

fn wire_cast<T: DeserializeOwned, E>(value: &impl Serialize) -> Result<T, PluginError<E>> {
    serde_json::to_value(value)
        .and_then(serde_json::from_value)
        .map_err(serialization_runtime)
}

#[allow(clippy::needless_pass_by_value)]
fn serialization_runtime<E>(error: serde_json::Error) -> PluginError<E> {
    PluginError::runtime(RuntimeFailure::Internal {
        detail: format!("Legal Hold wire serialization failed: {error}"),
    })
}

#[allow(clippy::needless_pass_by_value)]
fn storage_runtime<E>(error: StorageError) -> PluginError<E> {
    PluginError::runtime(RuntimeFailure::PluginFailure {
        detail: error.to_string(),
    })
}

fn parse_revision(value: &str) -> Option<i64> {
    value.parse::<i64>().ok().filter(|revision| *revision > 0)
}

fn valid_id(value: &str) -> bool {
    valid_text(value, MAX_ID_BYTES, false)
}

fn valid_idempotency_key(value: &str) -> bool {
    valid_text(value, MAX_IDEMPOTENCY_BYTES, false)
}

fn valid_text(value: &str, max_bytes: usize, allow_empty: bool) -> bool {
    value.len() <= max_bytes
        && (allow_empty || !value.trim().is_empty())
        && !value.chars().any(char::is_control)
}

fn valid_identifier(value: &str, max_bytes: usize) -> bool {
    valid_text(value, max_bytes, false) && !value.chars().any(char::is_whitespace)
}

fn validate_callers(callers: &[String]) -> Result<(), ()> {
    if callers.is_empty() || callers.len() > MAX_CALLERS {
        return Err(());
    }
    let mut unique = BTreeSet::new();
    for caller in callers {
        if !valid_identifier(caller, 256) || !unique.insert(caller) {
            return Err(());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use lenso_auth_sdk::ActorAssertionIssuer;
    use lenso_kernel::{CancellationToken, InvocationContext};
    use lenso_native_adapter::NativePluginRegistry;

    fn config() -> LegalHoldConfig {
        let issuer = ActorAssertionIssuer::new("auth.users", b"legal-hold-test-key");
        LegalHoldConfig::new(
            "legal_hold",
            "legal-hold/database-url",
            "auth.users",
            issuer.public_key_base64(),
            vec!["legal-api".to_owned()],
            vec!["privacy-retention".to_owned()],
        )
        .unwrap()
    }

    fn plugin() -> PostgresLegalHoldPlugin {
        PostgresLegalHoldPlugin {
            config: config(),
            secrets: Port::default(),
            membership: Port::default(),
            access: Port::default(),
            prepared: Rc::new(RefCell::new(None)),
        }
    }

    fn context(caller: &str) -> InvocationContext {
        InvocationContext::new(1, None, CancellationToken::new()).with_caller_instance(caller)
    }

    #[test]
    fn descriptor_declares_only_real_capabilities_and_dependencies() {
        let descriptor: serde_json::Value = serde_json::from_str(PLUGIN_DESCRIPTOR_JSON).unwrap();
        let provided = descriptor["provided_capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value["capability_id"].as_str().unwrap())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            provided,
            BTreeSet::from([legal::CAPABILITY_ID, guard::CAPABILITY_ID])
        );
        let required = descriptor["required_capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value["capability_id"].as_str().unwrap())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            required,
            BTreeSet::from([
                secrets::CAPABILITY_ID,
                membership::CAPABILITY_ID,
                access::CAPABILITY_ID,
            ])
        );
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
    fn configuration_rejects_ambient_and_duplicate_callers() {
        let mut invalid = config();
        invalid.admin_callers.clear();
        assert_eq!(
            invalid.validate(),
            Err(LegalHoldConfigError::InvalidAdminCallers)
        );
        let mut invalid = config();
        invalid.guard_callers.push("privacy-retention".to_owned());
        assert_eq!(
            invalid.validate(),
            Err(LegalHoldConfigError::InvalidGuardCallers)
        );
    }

    #[test]
    fn exact_guard_caller_is_checked_before_storage() {
        let request = CheckRetentionRequest {
            action_id: "retention_1".to_owned(),
            scope_kind: "organization".to_owned(),
            scope_id: "org_1".to_owned(),
            subject: "usr_1".to_owned(),
            mode: CheckRetentionRequestMode::Delete,
            reason: "expired".to_owned(),
        };
        let result = futures::executor::block_on(
            plugin().check_retention(context("untrusted-retention"), request),
        );
        assert_eq!(
            result,
            Err(PluginError::Domain(CheckRetentionError::Forbidden))
        );
    }
}
