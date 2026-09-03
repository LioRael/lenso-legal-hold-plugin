//! Console Agent Tools over an explicitly bound Legal Hold capability.

use lenso::prelude::*;
use lenso_capability_agent_tool_provider::{
    self as tool_contract, CatalogRequest, CatalogResponse, ContentType, ExecuteError,
    ExecuteRequest, ExecuteResponse, ExecutionFailedPayload, ToolDefinition, ToolExecutionClass,
};
use lenso_capability_legal_hold::{
    self as hold, AddScopeRequest, CreateHoldRequest, GetHoldRequest, ListActivityRequest,
    ListHoldsRequest, ReleaseHoldRequest, RemoveScopeRequest,
};
use lenso_kernel::RuntimeFailure;
use serde::{Serialize, de::DeserializeOwned};

const CREATE: &str = "legal_hold_create";
const GET: &str = "legal_hold_get";
const LIST: &str = "legal_hold_list";
const ADD_SCOPE: &str = "legal_hold_add_scope";
const REMOVE_SCOPE: &str = "legal_hold_remove_scope";
const RELEASE: &str = "legal_hold_release";
const ACTIVITY: &str = "legal_hold_list_activity";

#[lenso::plugin]
#[derive(Clone, Debug)]
struct LegalHoldAgentToolsPlugin {
    legal_hold: Port<hold::LegalHoldClient>,
}

#[lenso::provides(tool_contract::ToolProvider)]
impl LegalHoldAgentToolsPlugin {
    fn catalog(
        &self,
        _context: Ctx,
        _request: CatalogRequest,
    ) -> impl std::future::Future<Output = PluginResult<CatalogResponse, tool_contract::CatalogError>>
    {
        let _ = self;
        futures::future::ready(Ok(CatalogResponse {
            tools: tool_definitions(),
        }))
    }

    async fn execute(
        &self,
        context: Ctx,
        request: ExecuteRequest,
    ) -> PluginResult<ExecuteResponse, ExecuteError> {
        macro_rules! invoke {
            ($ty:ty, $method:ident, $domain:path, $runtime:path, $name:expr) => {{
                let arguments = decode::<$ty>(&request)?;
                match self.legal_hold.$method(context, arguments).await {
                    Ok(response) => success($name, &response),
                    Err($domain(error)) => Err(PluginError::domain(map_error(&error))),
                    Err($runtime(error)) => Err(PluginError::runtime(error)),
                }
            }};
        }
        match request.name.as_str() {
            GET => invoke!(
                GetHoldRequest,
                get_hold_with_context,
                hold::LegalHoldGetHoldInvocationError::Domain,
                hold::LegalHoldGetHoldInvocationError::Runtime,
                GET
            ),
            LIST => invoke!(
                ListHoldsRequest,
                list_holds_with_context,
                hold::LegalHoldListHoldsInvocationError::Domain,
                hold::LegalHoldListHoldsInvocationError::Runtime,
                LIST
            ),
            ACTIVITY => invoke!(
                ListActivityRequest,
                list_activity_with_context,
                hold::LegalHoldListActivityInvocationError::Domain,
                hold::LegalHoldListActivityInvocationError::Runtime,
                ACTIVITY
            ),
            CREATE => invoke!(
                CreateHoldRequest,
                create_hold_with_context,
                hold::LegalHoldCreateHoldInvocationError::Domain,
                hold::LegalHoldCreateHoldInvocationError::Runtime,
                CREATE
            ),
            ADD_SCOPE => invoke!(
                AddScopeRequest,
                add_scope_with_context,
                hold::LegalHoldAddScopeInvocationError::Domain,
                hold::LegalHoldAddScopeInvocationError::Runtime,
                ADD_SCOPE
            ),
            REMOVE_SCOPE => invoke!(
                RemoveScopeRequest,
                remove_scope_with_context,
                hold::LegalHoldRemoveScopeInvocationError::Domain,
                hold::LegalHoldRemoveScopeInvocationError::Runtime,
                REMOVE_SCOPE
            ),
            RELEASE => invoke!(
                ReleaseHoldRequest,
                release_hold_with_context,
                hold::LegalHoldReleaseHoldInvocationError::Domain,
                hold::LegalHoldReleaseHoldInvocationError::Runtime,
                RELEASE
            ),
            _ => Err(PluginError::domain(ExecuteError::NotFound)),
        }
    }
}

fn tool_definitions() -> Vec<ToolDefinition> {
    vec![
        tool(
            GET,
            "Get one legal hold for authorized review.",
            include_str!("../../lenso-capability-legal-hold/schemas/get-hold-request.schema.json"),
            ToolExecutionClass::ParallelSafe,
        ),
        tool(
            LIST,
            "List legal holds with bounded cursor pagination.",
            include_str!(
                "../../lenso-capability-legal-hold/schemas/list-holds-request.schema.json"
            ),
            ToolExecutionClass::ParallelSafe,
        ),
        tool(
            ACTIVITY,
            "List bounded activity for one legal hold.",
            include_str!(
                "../../lenso-capability-legal-hold/schemas/list-activity-request.schema.json"
            ),
            ToolExecutionClass::ParallelSafe,
        ),
        tool(
            CREATE,
            "Create a legal hold with a caller-scoped idempotency key.",
            include_str!(
                "../../lenso-capability-legal-hold/schemas/create-hold-request.schema.json"
            ),
            ToolExecutionClass::Exclusive,
        ),
        tool(
            ADD_SCOPE,
            "Add one exact scope using the current expected revision.",
            include_str!(
                "../../lenso-capability-legal-hold/schemas/mutate-scope-request.schema.json"
            ),
            ToolExecutionClass::Exclusive,
        ),
        tool(
            REMOVE_SCOPE,
            "Remove one exact scope using the current expected revision.",
            include_str!(
                "../../lenso-capability-legal-hold/schemas/mutate-scope-request.schema.json"
            ),
            ToolExecutionClass::Exclusive,
        ),
        tool(
            RELEASE,
            "Irreversibly release a legal hold using the current expected revision.",
            include_str!(
                "../../lenso-capability-legal-hold/schemas/release-hold-request.schema.json"
            ),
            ToolExecutionClass::Exclusive,
        ),
    ]
}

fn tool(
    name: &str,
    description: &str,
    schema: &str,
    execution: ToolExecutionClass,
) -> ToolDefinition {
    ToolDefinition {
        name: name.to_owned(),
        description: description.to_owned(),
        input_schema_json: serde_json::from_str::<serde_json::Value>(schema)
            .expect("Legal Hold Tool schema must be valid JSON")
            .to_string()
            .try_into()
            .expect("Legal Hold Tool schema must remain valid JSON"),
        execution,
    }
}

fn decode<T: DeserializeOwned>(request: &ExecuteRequest) -> PluginResult<T, ExecuteError> {
    serde_json::from_str(request.arguments_json.as_str())
        .map_err(|_| PluginError::domain(ExecuteError::InvalidArguments))
}

fn success<T: Serialize>(name: &str, response: &T) -> PluginResult<ExecuteResponse, ExecuteError> {
    let content = serde_json::to_string_pretty(response).map_err(|error| {
        PluginError::runtime(RuntimeFailure::PluginFailure {
            detail: format!("Legal Hold Tool could not serialize its response: {error}"),
        })
    })?;
    Ok(ExecuteResponse {
        content_blocks: None,
        content,
        content_type: ContentType::Text,
        metadata_json: serde_json::json!({ "tool": name })
            .to_string()
            .try_into()
            .expect("Legal Hold Tool metadata must be valid JSON"),
    })
}

trait DomainError {
    fn tool_error(&self) -> ExecuteError;
}
fn map_error(error: &impl DomainError) -> ExecuteError {
    error.tool_error()
}
fn rejected(code: &str) -> ExecuteError {
    ExecuteError::ExecutionFailed {
        payload: ExecutionFailedPayload {
            reason_code: code.to_owned(),
            message: "Legal Hold rejected the operation.".to_owned(),
            details_json: serde_json::json!({ "domain_error": code })
                .to_string()
                .try_into()
                .expect("Legal Hold Tool error metadata must be valid JSON"),
        },
    }
}
macro_rules! impl_domain_error {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl DomainError for $ty {
                fn tool_error(&self) -> ExecuteError {
                    match self {
                        Self::InvalidRequest => ExecuteError::InvalidArguments,
                        Self::NotFound => ExecuteError::NotFound,
                        Self::Forbidden | Self::Unauthenticated => ExecuteError::PermissionDenied,
                        Self::HoldReleased => rejected("hold_released"),
                        Self::IdempotencyConflict => rejected("idempotency_conflict"),
                        Self::RevisionConflict => rejected("revision_conflict"),
                        Self::ScopeConflict => rejected("scope_conflict"),
                        Self::Unknown(_) => rejected("unknown_domain_error"),
                    }
                }
            }
        )+
    };
}
impl_domain_error!(
    hold::AddScopeError,
    hold::CreateHoldError,
    hold::GetHoldError,
    hold::ListActivityError,
    hold::ListHoldsError,
    hold::ReleaseHoldError,
    hold::RemoveScopeError
);

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn descriptor_and_catalog_keep_admin_and_guard_roles_separate() {
        let descriptor: serde_json::Value = serde_json::from_str(PLUGIN_DESCRIPTOR_JSON).unwrap();
        assert_eq!(descriptor["plugin_id"], "lenso.legal-hold.agent-tools");
        let required = descriptor["required_capabilities"].as_array().unwrap();
        assert_eq!(required.len(), 1);
        assert_eq!(required[0]["capability_id"], "lenso.legal-hold@1");
        let tools = tool_definitions();
        assert_eq!(tools.len(), 7);
        assert_eq!(
            tools
                .iter()
                .filter(|tool| tool.execution == ToolExecutionClass::ParallelSafe)
                .count(),
            3
        );
        assert!(tools.iter().all(|tool| !tool.name.contains("guard")));
    }
}
