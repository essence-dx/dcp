//! Property-based tests for MCP compatibility layer.
//!
//! Feature: dcp-protocol, Property 14: MCP Translation Round-Trip

use dcp::compat::{
    adapter::AdapterError,
    json_rpc::{JsonRpcError, JsonRpcParser, JsonRpcRequest, JsonRpcResponse, RequestId},
};
use dcp::dispatch::ToolResult;
use dcp::{CapabilityManifest, DCPError, McpAdapter};
use proptest::prelude::*;
use serde_json::Value;

/// Strategy to generate a valid method name
fn arb_method() -> impl Strategy<Value = String> {
    prop::string::string_regex("[a-z]+(/[a-z]+)?")
        .unwrap()
        .prop_filter("non-empty method", |s| !s.is_empty())
}

#[cfg(test)]
mod security_tests {
    use super::*;
    use dcp::binary::ArgType;
    use dcp::dispatch::{BinaryTrieRouter, SharedArgs, ToolHandler};
    use dcp::protocol::{FieldDef, InputSchema, ToolSchema};
    use dcp::security::{SecurityAuditAction, REDACTED};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    struct CountingTool {
        calls: Arc<AtomicUsize>,
    }

    struct InspectingTool {
        calls: Arc<AtomicUsize>,
        last_arg_len: Arc<AtomicUsize>,
    }

    struct RequiredBoolTool {
        calls: Arc<AtomicUsize>,
        schema: ToolSchema,
    }

    impl CountingTool {
        fn new(calls: Arc<AtomicUsize>) -> Self {
            Self { calls }
        }
    }

    impl InspectingTool {
        fn new(calls: Arc<AtomicUsize>, last_arg_len: Arc<AtomicUsize>) -> Self {
            Self {
                calls,
                last_arg_len,
            }
        }
    }

    impl RequiredBoolTool {
        fn new(calls: Arc<AtomicUsize>) -> Self {
            let mut input = InputSchema::new();
            input.add_field(FieldDef::new("enabled", ArgType::Bool, 0, 1));
            input.set_required(0);

            Self {
                calls,
                schema: ToolSchema {
                    name: "secure",
                    id: 7,
                    description: "secure tool",
                    input,
                },
            }
        }
    }

    impl ToolHandler for CountingTool {
        fn execute(&self, _args: &SharedArgs) -> Result<ToolResult, DCPError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(ToolResult::empty())
        }

        fn schema(&self) -> &ToolSchema {
            static SCHEMA: ToolSchema = ToolSchema {
                name: "secure",
                id: 7,
                description: "secure tool",
                input: InputSchema {
                    required: 0,
                    fields: Vec::new(),
                },
            };
            &SCHEMA
        }
    }

    impl ToolHandler for InspectingTool {
        fn execute(&self, args: &SharedArgs) -> Result<ToolResult, DCPError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.last_arg_len.store(args.data().len(), Ordering::SeqCst);
            Ok(ToolResult::empty())
        }

        fn schema(&self) -> &ToolSchema {
            static SCHEMA: ToolSchema = ToolSchema {
                name: "secure",
                id: 7,
                description: "secure tool",
                input: InputSchema {
                    required: 0,
                    fields: Vec::new(),
                },
            };
            &SCHEMA
        }
    }

    impl ToolHandler for RequiredBoolTool {
        fn execute(&self, _args: &SharedArgs) -> Result<ToolResult, DCPError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(ToolResult::empty())
        }

        fn schema(&self) -> &ToolSchema {
            &self.schema
        }
    }

    fn router_with_counting_tool(calls: Arc<AtomicUsize>) -> BinaryTrieRouter {
        let mut router = BinaryTrieRouter::new();
        router.register(Box::new(CountingTool::new(calls))).unwrap();
        router
    }

    fn router_with_inspecting_tool(
        calls: Arc<AtomicUsize>,
        last_arg_len: Arc<AtomicUsize>,
    ) -> BinaryTrieRouter {
        let mut router = BinaryTrieRouter::new();
        router
            .register(Box::new(InspectingTool::new(calls, last_arg_len)))
            .unwrap();
        router
    }

    fn router_with_required_bool_tool(calls: Arc<AtomicUsize>) -> BinaryTrieRouter {
        let mut router = BinaryTrieRouter::new();
        router
            .register(Box::new(RequiredBoolTool::new(calls)))
            .unwrap();
        router
    }

    #[test]
    fn legacy_mcp_adapter_denies_tool_calls_without_negotiated_capability() {
        let calls = Arc::new(AtomicUsize::new(0));
        let router = router_with_counting_tool(Arc::clone(&calls));
        let mut adapter = McpAdapter::new();
        adapter.register_tool("secure", 7).unwrap();

        let response = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"secure"},"id":1}"#,
                &router,
            )
            .unwrap();
        let parsed = JsonRpcParser::parse_response(&response).unwrap();

        assert_eq!(parsed.error.unwrap().code, -32001);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn legacy_mcp_adapter_lists_only_negotiated_tools() {
        let mut adapter = McpAdapter::new();
        adapter.register_tool("visible", 7).unwrap();
        adapter.register_tool("hidden", 8).unwrap();
        let mut capabilities = CapabilityManifest::new(1);
        capabilities.set_tool(7);
        let adapter = adapter.with_negotiated_capabilities(capabilities);

        let request = JsonRpcRequest::new("tools/list", None, RequestId::Number(1));
        let response = adapter.handle_tools_list(&request).unwrap();
        let parsed = JsonRpcParser::parse_response(&response).unwrap();
        let tools = parsed.result.unwrap()["tools"].as_array().unwrap().clone();

        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["name"], "visible");
    }

    #[test]
    fn legacy_mcp_adapter_rejects_tool_registration_outside_manifest_capacity() {
        let mut adapter = McpAdapter::new();

        let err = adapter
            .register_tool("overflow", CapabilityManifest::MAX_TOOLS as u16)
            .unwrap_err();

        assert!(matches!(
            err,
            AdapterError::CapacityExceeded { kind: "tool", .. }
        ));
        assert_eq!(adapter.tool_count(), 0);
        assert_eq!(adapter.resolve_tool_name("overflow"), None);
    }

    #[test]
    fn legacy_mcp_adapter_rejects_duplicate_tool_names_and_ids() {
        let mut adapter = McpAdapter::new();

        let tool_id = adapter.register_tool("visible", 7).unwrap();
        let duplicate_name = adapter.register_tool("visible", 8).unwrap_err();
        let duplicate_id = adapter.register_tool("hidden", 7).unwrap_err();

        assert_eq!(tool_id, 7);
        assert!(matches!(duplicate_name, AdapterError::InvalidRequest(_)));
        assert!(matches!(duplicate_id, AdapterError::InvalidRequest(_)));
        assert_eq!(adapter.tool_count(), 1);
        assert_eq!(adapter.resolve_tool_name("visible"), Some(7));
        assert_eq!(adapter.resolve_tool_name("hidden"), None);
        assert_eq!(adapter.resolve_tool_id(7), Some("visible"));
        assert_eq!(adapter.resolve_tool_id(8), None);
    }

    #[test]
    fn legacy_mcp_adapter_audits_rejected_tool_registration_without_leaking_secret_name() {
        let mut adapter = McpAdapter::new();

        let err = adapter
            .register_tool(
                "authorization=Bearer plain-secret",
                CapabilityManifest::MAX_TOOLS as u16,
            )
            .unwrap_err();

        assert!(matches!(
            err,
            AdapterError::CapacityExceeded { kind: "tool", .. }
        ));
        let events = adapter.security_audit().events();
        let event = events
            .iter()
            .find(|event| event.reason == "tool_registration_capacity_exceeded")
            .expect("registration failure audit receipt");

        assert_eq!(event.action, SecurityAuditAction::ValidationRejected);
        assert_eq!(
            event.fields.get("adapter").map(String::as_str),
            Some("legacy_mcp")
        );
        assert_eq!(
            event.fields.get("operation").map(String::as_str),
            Some("tool_registration")
        );
        assert_eq!(
            event.fields.get("tool_name").map(String::as_str),
            Some(REDACTED)
        );

        let audit_dump = format!("{events:?}");
        assert!(!audit_dump.contains("plain-secret"));
        assert!(!audit_dump.contains("Bearer"));
    }

    #[test]
    fn legacy_mcp_adapter_initialize_advertises_only_registered_tool_surface() {
        let request = JsonRpcRequest::new("initialize", None, RequestId::Number(1));

        let empty = McpAdapter::new();
        let empty_response =
            JsonRpcParser::parse_response(&empty.handle_initialize(&request).unwrap()).unwrap();
        let empty_result = empty_response.result.unwrap();
        let empty_capabilities = empty_result["capabilities"].as_object().unwrap();
        assert!(!empty_capabilities.contains_key("tools"));
        assert!(!empty_capabilities.contains_key("resources"));
        assert!(!empty_capabilities.contains_key("prompts"));

        let mut adapter = McpAdapter::new();
        adapter.register_tool("visible", 7).unwrap();
        let response =
            JsonRpcParser::parse_response(&adapter.handle_initialize(&request).unwrap()).unwrap();
        let result = response.result.unwrap();
        let capabilities = result["capabilities"].as_object().unwrap();

        assert!(capabilities.contains_key("tools"));
        assert!(!capabilities.contains_key("resources"));
        assert!(!capabilities.contains_key("prompts"));
    }

    #[test]
    fn legacy_mcp_adapter_executes_negotiated_tool() {
        let calls = Arc::new(AtomicUsize::new(0));
        let router = router_with_counting_tool(Arc::clone(&calls));
        let mut adapter = McpAdapter::new();
        adapter.register_tool("secure", 7).unwrap();
        let mut capabilities = CapabilityManifest::new(1);
        capabilities.set_tool(7);
        let adapter = adapter.with_negotiated_capabilities(capabilities);

        let response = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"secure"},"id":1}"#,
                &router,
            )
            .unwrap();
        let parsed = JsonRpcParser::parse_response(&response).unwrap();

        assert!(parsed.is_success());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn legacy_mcp_adapter_audits_schema_validation_failure_without_dispatch_or_secret_leak() {
        let calls = Arc::new(AtomicUsize::new(0));
        let router = router_with_required_bool_tool(Arc::clone(&calls));
        let mut adapter = McpAdapter::new();
        adapter.register_tool("secure", 7).unwrap();
        let mut capabilities = CapabilityManifest::new(1);
        capabilities.set_tool(7);
        let adapter = adapter.with_negotiated_capabilities(capabilities);

        let response = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"secure","arguments":{},"_meta":{"token":"api_key=plain-secret"}},"id":12}"#,
                &router,
            )
            .unwrap();
        let parsed = JsonRpcParser::parse_response(&response).unwrap();

        assert!(parsed.is_error());
        assert_eq!(parsed.error.unwrap().code, -32602);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(!response.contains("plain-secret"));
        assert!(!response.contains("api_key"));
        assert!(adapter.security_audit().events().iter().any(|event| {
            event.action == SecurityAuditAction::ValidationRejected
                && event.reason == "invalid_params"
                && event.method.as_deref() == Some("tools/call")
                && event.request_id.as_deref() == Some("12")
        }));

        let audit_dump = format!("{:?}", adapter.security_audit().events());
        assert!(!audit_dump.contains("plain-secret"));
        assert!(!audit_dump.contains("api_key"));
    }

    #[test]
    fn legacy_mcp_direct_tools_call_audits_missing_params_and_name_without_secret_leak() {
        let calls = Arc::new(AtomicUsize::new(0));
        let router = router_with_counting_tool(Arc::clone(&calls));
        let mut adapter = McpAdapter::new();
        adapter.register_tool("secure", 7).unwrap();
        let mut capabilities = CapabilityManifest::new(1);
        capabilities.set_tool(7);
        let adapter = adapter.with_negotiated_capabilities(capabilities);

        let missing_params = JsonRpcRequest::new("tools/call", None, RequestId::Number(71));
        let response = adapter
            .handle_tools_call(&missing_params, &router)
            .expect("missing params should produce an error response");
        let parsed = JsonRpcParser::parse_response(&response).unwrap();
        assert!(parsed.is_error());
        assert_eq!(parsed.error.unwrap().code, -32600);

        let missing_name = JsonRpcRequest::new(
            "tools/call",
            Some(serde_json::json!({
                "arguments": { "api_key": "plain-secret" }
            })),
            RequestId::Number(72),
        );
        let response = adapter
            .handle_tools_call(&missing_name, &router)
            .expect("missing name should produce an error response");
        let parsed = JsonRpcParser::parse_response(&response).unwrap();
        assert!(parsed.is_error());
        assert_eq!(parsed.error.unwrap().code, -32600);

        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(!response.contains("plain-secret"));
        assert!(!response.contains("api_key"));
        assert!(adapter.security_audit().events().iter().any(|event| {
            event.action == SecurityAuditAction::ValidationRejected
                && event.reason == "invalid_request"
                && event.method.as_deref() == Some("tools/call")
                && event.request_id.as_deref() == Some("71")
        }));
        assert!(adapter.security_audit().events().iter().any(|event| {
            event.action == SecurityAuditAction::ValidationRejected
                && event.reason == "invalid_request"
                && event.method.as_deref() == Some("tools/call")
                && event.request_id.as_deref() == Some("72")
        }));

        let audit_dump = format!("{:?}", adapter.security_audit().events());
        assert!(!audit_dump.contains("plain-secret"));
        assert!(!audit_dump.contains("api_key"));
    }

    #[test]
    fn legacy_mcp_adapter_rejects_replayed_tool_call_request_id_without_dispatch() {
        let calls = Arc::new(AtomicUsize::new(0));
        let router = router_with_counting_tool(Arc::clone(&calls));
        let mut adapter = McpAdapter::new();
        adapter.register_tool("secure", 7).unwrap();
        let mut capabilities = CapabilityManifest::new(1);
        capabilities.set_tool(7);
        let adapter = adapter.with_negotiated_capabilities(capabilities);

        let request = r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"secure","arguments":{},"_meta":{"token":"api_key=plain-secret"}},"id":2}"#;
        let first = adapter.handle_request(request, &router).unwrap();
        let first = JsonRpcParser::parse_response(&first).unwrap();
        assert!(first.is_success());
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let replay = adapter.handle_request(request, &router).unwrap();
        let parsed = JsonRpcParser::parse_response(&replay).unwrap();

        assert!(parsed.is_error());
        assert_eq!(parsed.error.unwrap().code, -32002);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(!replay.contains("plain-secret"));
        assert!(!replay.contains("api_key"));
        assert!(adapter.security_audit().events().iter().any(|event| {
            event.action == SecurityAuditAction::ReplayRejected
                && event.reason == "request_replay"
                && event.method.as_deref() == Some("tools/call")
                && event.request_id.as_deref() == Some("2")
        }));

        let audit_dump = format!("{:?}", adapter.security_audit().events());
        assert!(!audit_dump.contains("plain-secret"));
        assert!(!audit_dump.contains("api_key"));
    }

    #[test]
    fn legacy_mcp_adapter_rejects_non_object_meta_before_dispatch() {
        let calls = Arc::new(AtomicUsize::new(0));
        let router = router_with_counting_tool(Arc::clone(&calls));
        let mut adapter = McpAdapter::new();
        adapter.register_tool("secure", 7).unwrap();
        let mut capabilities = CapabilityManifest::new(1);
        capabilities.set_tool(7);
        let adapter = adapter.with_negotiated_capabilities(capabilities);

        let response = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"secure","arguments":{},"_meta":"api_key=plain-secret"},"id":17}"#,
                &router,
            )
            .unwrap();
        let parsed = JsonRpcParser::parse_response(&response).unwrap();

        assert!(parsed.is_error());
        assert_eq!(parsed.error.unwrap().code, -32602);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(!response.contains("plain-secret"));
        assert!(!response.contains("api_key"));
        assert!(adapter.security_audit().events().iter().any(|event| {
            event.action == SecurityAuditAction::ValidationRejected
                && event.reason == "invalid_params"
                && event.method.as_deref() == Some("tools/call")
                && event.request_id.as_deref() == Some("17")
        }));

        let audit_dump = format!("{:?}", adapter.security_audit().events());
        assert!(!audit_dump.contains("plain-secret"));
        assert!(!audit_dump.contains("api_key"));
    }

    #[test]
    fn legacy_mcp_adapter_does_not_execute_tool_call_notification() {
        let calls = Arc::new(AtomicUsize::new(0));
        let router = router_with_counting_tool(Arc::clone(&calls));
        let mut adapter = McpAdapter::new();
        adapter.register_tool("secure", 7).unwrap();
        let mut capabilities = CapabilityManifest::new(1);
        capabilities.set_tool(7);
        let adapter = adapter.with_negotiated_capabilities(capabilities);

        let response = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"secure"}}"#,
                &router,
            )
            .unwrap();
        let parsed = JsonRpcParser::parse_response(&response).unwrap();

        assert!(parsed.is_error());
        assert_eq!(parsed.error.unwrap().code, -32600);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(adapter.security_audit().events().iter().any(|event| {
            event.action == SecurityAuditAction::RequestRejected
                && event.reason == "notification_not_allowed"
                && event.method.as_deref() == Some("tools/call")
        }));
    }

    #[test]
    fn legacy_mcp_adapter_audits_unknown_methods_without_leaking_secret_method_text() {
        let router = BinaryTrieRouter::new();
        let adapter = McpAdapter::new();

        let response = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"unknown/access_token=plain-secret","id":9}"#,
                &router,
            )
            .unwrap();
        let parsed = JsonRpcParser::parse_response(&response).unwrap();

        assert!(parsed.is_error());
        assert_eq!(parsed.error.unwrap().code, -32601);
        assert!(!response.contains("plain-secret"));
        assert!(!response.contains("access_token"));
        assert!(adapter.security_audit().events().iter().any(|event| {
            event.action == SecurityAuditAction::RequestRejected
                && event.reason == "method_not_found"
                && event.request_id.as_deref() == Some("9")
        }));

        let audit_dump = format!("{:?}", adapter.security_audit().events());
        assert!(!audit_dump.contains("plain-secret"));
        assert!(!audit_dump.contains("access_token"));
    }

    #[test]
    fn legacy_mcp_adapter_returns_sanitized_jsonrpc_errors_for_malformed_requests() {
        let router = BinaryTrieRouter::new();
        let adapter = McpAdapter::new();

        let cases = [
            (
                r#"{"jsonrpc":"2.0","method":"tools/list","id":"access_token=plain-secret""#,
                -32700,
                "parse_error",
            ),
            (r#"[]"#, -32600, "batch_unsupported"),
            (
                r#"{"jsonrpc":"2.0","method":42,"id":1}"#,
                -32600,
                "invalid_request",
            ),
        ];

        for (json, code, reason) in cases {
            let response = adapter.handle_request(json, &router).unwrap();
            let parsed = JsonRpcParser::parse_response(&response).unwrap();

            assert_eq!(parsed.id, RequestId::Null);
            assert_eq!(parsed.error.unwrap().code, code);
            assert!(!response.contains("plain-secret"));
            assert!(!response.contains("access_token"));
            assert!(adapter.security_audit().events().iter().any(|event| {
                event.action == SecurityAuditAction::ValidationRejected && event.reason == reason
            }));
        }

        let audit_dump = format!("{:?}", adapter.security_audit().events());
        assert!(!audit_dump.contains("plain-secret"));
        assert!(!audit_dump.contains("access_token"));
    }

    #[test]
    fn legacy_mcp_adapter_returns_request_too_large_response_without_leaking_payload() {
        let router = BinaryTrieRouter::new();
        let adapter = McpAdapter::new().with_max_request_size(64);
        let secret = "api_key=plain-secret";
        let request = format!(
            r#"{{"jsonrpc":"2.0","method":"tools/list","params":{{"token":"{secret}","padding":"{}"}},"id":1}}"#,
            "x".repeat(128)
        );

        let response = adapter.handle_request(&request, &router).unwrap();
        let parsed = JsonRpcParser::parse_response(&response).unwrap();

        assert_eq!(parsed.id, RequestId::Null);
        assert_eq!(parsed.error.unwrap().code, -32600);
        assert!(!response.contains(secret));
        assert!(!response.contains("api_key"));
        assert!(adapter.security_audit().events().iter().any(|event| {
            event.action == SecurityAuditAction::ValidationRejected
                && event.reason == "request_too_large"
        }));

        let audit_dump = format!("{:?}", adapter.security_audit().events());
        assert!(!audit_dump.contains(secret));
        assert!(!audit_dump.contains("api_key"));
    }

    #[test]
    fn legacy_mcp_adapter_returns_sanitized_error_for_malformed_tools_call_params() {
        let calls = Arc::new(AtomicUsize::new(0));
        let router = router_with_counting_tool(Arc::clone(&calls));
        let mut adapter = McpAdapter::new();
        adapter.register_tool("secure", 7).unwrap();
        let mut capabilities = CapabilityManifest::new(1);
        capabilities.set_tool(7);
        let adapter = adapter.with_negotiated_capabilities(capabilities);

        let response = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"tools/call","params":{"arguments":{"token":"api_key=plain-secret"}},"id":5}"#,
                &router,
            )
            .unwrap();
        let parsed = JsonRpcParser::parse_response(&response).unwrap();

        assert_eq!(parsed.id, RequestId::Number(5));
        assert_eq!(parsed.error.unwrap().code, -32600);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(!response.contains("plain-secret"));
        assert!(!response.contains("api_key"));
        assert!(adapter.security_audit().events().iter().any(|event| {
            event.action == SecurityAuditAction::ValidationRejected
                && event.reason == "invalid_request"
                && event.method.as_deref() == Some("tools/call")
                && event.request_id.as_deref() == Some("5")
        }));

        let audit_dump = format!("{:?}", adapter.security_audit().events());
        assert!(!audit_dump.contains("plain-secret"));
        assert!(!audit_dump.contains("api_key"));
    }

    #[test]
    fn legacy_mcp_adapter_rejects_non_object_arguments_before_dispatch() {
        let calls = Arc::new(AtomicUsize::new(0));
        let router = router_with_counting_tool(Arc::clone(&calls));
        let mut adapter = McpAdapter::new();
        adapter.register_tool("secure", 7).unwrap();
        let mut capabilities = CapabilityManifest::new(1);
        capabilities.set_tool(7);
        let adapter = adapter.with_negotiated_capabilities(capabilities);

        let response = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"secure","arguments":["api_key=plain-secret"]},"id":12}"#,
                &router,
            )
            .unwrap();
        let parsed = JsonRpcParser::parse_response(&response).unwrap();

        assert_eq!(parsed.id, RequestId::Number(12));
        assert_eq!(parsed.error.unwrap().code, -32602);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(!response.contains("plain-secret"));
        assert!(!response.contains("api_key"));
        assert!(adapter.security_audit().events().iter().any(|event| {
            event.action == SecurityAuditAction::ValidationRejected
                && event.reason == "invalid_params"
                && event.method.as_deref() == Some("tools/call")
                && event.request_id.as_deref() == Some("12")
        }));

        let audit_dump = format!("{:?}", adapter.security_audit().events());
        assert!(!audit_dump.contains("plain-secret"));
        assert!(!audit_dump.contains("api_key"));
    }

    #[test]
    fn legacy_mcp_adapter_rejects_non_empty_object_arguments_before_dispatch() {
        let calls = Arc::new(AtomicUsize::new(0));
        let router = router_with_counting_tool(Arc::clone(&calls));
        let mut adapter = McpAdapter::new();
        adapter.register_tool("secure", 7).unwrap();
        let mut capabilities = CapabilityManifest::new(1);
        capabilities.set_tool(7);
        let adapter = adapter.with_negotiated_capabilities(capabilities);

        let response = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"secure","arguments":{"token":"authorization=Bearer plain-secret"}},"id":13}"#,
                &router,
            )
            .unwrap();
        let parsed = JsonRpcParser::parse_response(&response).unwrap();

        assert_eq!(parsed.id, RequestId::Number(13));
        assert_eq!(parsed.error.unwrap().code, -32602);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(!response.contains("plain-secret"));
        assert!(!response.contains("authorization"));
        assert!(adapter.security_audit().events().iter().any(|event| {
            event.action == SecurityAuditAction::ValidationRejected
                && event.reason == "invalid_params"
                && event.method.as_deref() == Some("tools/call")
                && event.request_id.as_deref() == Some("13")
        }));

        let audit_dump = format!("{:?}", adapter.security_audit().events());
        assert!(!audit_dump.contains("plain-secret"));
        assert!(!audit_dump.contains("authorization"));
    }

    #[test]
    fn legacy_mcp_adapter_rejects_tools_call_params_array_before_dispatch() {
        let calls = Arc::new(AtomicUsize::new(0));
        let router = router_with_counting_tool(Arc::clone(&calls));
        let mut adapter = McpAdapter::new();
        adapter.register_tool("secure", 7).unwrap();
        let mut capabilities = CapabilityManifest::new(1);
        capabilities.set_tool(7);
        let adapter = adapter.with_negotiated_capabilities(capabilities);

        let response = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"tools/call","params":["secure","api_key=plain-secret"],"id":15}"#,
                &router,
            )
            .unwrap();
        let parsed = JsonRpcParser::parse_response(&response).unwrap();

        assert_eq!(parsed.id, RequestId::Number(15));
        assert_eq!(parsed.error.unwrap().code, -32602);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(!response.contains("plain-secret"));
        assert!(!response.contains("api_key"));
        assert!(adapter.security_audit().events().iter().any(|event| {
            event.action == SecurityAuditAction::ValidationRejected
                && event.reason == "invalid_params"
                && event.method.as_deref() == Some("tools/call")
                && event.request_id.as_deref() == Some("15")
        }));

        let audit_dump = format!("{:?}", adapter.security_audit().events());
        assert!(!audit_dump.contains("plain-secret"));
        assert!(!audit_dump.contains("api_key"));
    }

    #[test]
    fn legacy_mcp_adapter_rejects_extra_tools_call_param_before_dispatch() {
        let calls = Arc::new(AtomicUsize::new(0));
        let router = router_with_counting_tool(Arc::clone(&calls));
        let mut adapter = McpAdapter::new();
        adapter.register_tool("secure", 7).unwrap();
        let mut capabilities = CapabilityManifest::new(1);
        capabilities.set_tool(7);
        let adapter = adapter.with_negotiated_capabilities(capabilities);

        let response = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"secure","api_key":"plain-secret"},"id":16}"#,
                &router,
            )
            .unwrap();
        let parsed = JsonRpcParser::parse_response(&response).unwrap();

        assert_eq!(parsed.id, RequestId::Number(16));
        assert_eq!(parsed.error.unwrap().code, -32602);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(!response.contains("plain-secret"));
        assert!(!response.contains("api_key"));
        assert!(adapter.security_audit().events().iter().any(|event| {
            event.action == SecurityAuditAction::ValidationRejected
                && event.reason == "invalid_params"
                && event.method.as_deref() == Some("tools/call")
                && event.request_id.as_deref() == Some("16")
        }));

        let audit_dump = format!("{:?}", adapter.security_audit().events());
        assert!(!audit_dump.contains("plain-secret"));
        assert!(!audit_dump.contains("api_key"));
    }

    #[test]
    fn legacy_mcp_adapter_empty_object_arguments_do_not_pass_raw_payload() {
        let calls = Arc::new(AtomicUsize::new(0));
        let last_arg_len = Arc::new(AtomicUsize::new(usize::MAX));
        let router = router_with_inspecting_tool(Arc::clone(&calls), Arc::clone(&last_arg_len));
        let mut adapter = McpAdapter::new();
        adapter.register_tool("secure", 7).unwrap();
        let mut capabilities = CapabilityManifest::new(1);
        capabilities.set_tool(7);
        let adapter = adapter.with_negotiated_capabilities(capabilities);

        let response = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"secure","arguments":{}},"id":14}"#,
                &router,
            )
            .unwrap();
        let parsed = JsonRpcParser::parse_response(&response).unwrap();

        assert!(parsed.is_success());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(last_arg_len.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn legacy_mcp_adapter_direct_initialize_rejects_notifications_before_success() {
        let adapter = McpAdapter::new();
        let request = JsonRpcRequest::notification(
            "initialize",
            Some(serde_json::json!({
                "token": "api_key=plain-secret"
            })),
        );

        let response = adapter.handle_initialize(&request).unwrap();
        let parsed = JsonRpcParser::parse_response(&response).unwrap();

        assert_eq!(parsed.id, RequestId::Null);
        assert_eq!(parsed.error.unwrap().code, -32600);
        assert!(!response.contains("plain-secret"));
        assert!(!response.contains("api_key"));
        assert!(adapter.security_audit().events().iter().any(|event| {
            event.action == SecurityAuditAction::ValidationRejected
                && event.reason == "invalid_request"
                && event.method.as_deref() == Some("initialize")
        }));

        let audit_dump = format!("{:?}", adapter.security_audit().events());
        assert!(!audit_dump.contains("plain-secret"));
        assert!(!audit_dump.contains("api_key"));
    }

    #[test]
    fn legacy_mcp_adapter_direct_initialize_rejects_wrong_method_before_success() {
        let adapter = McpAdapter::new();
        let request = JsonRpcRequest::new("tools/list", None, RequestId::Number(10));

        let response = adapter.handle_initialize(&request).unwrap();
        let parsed = JsonRpcParser::parse_response(&response).unwrap();

        assert_eq!(parsed.id, RequestId::Number(10));
        assert_eq!(parsed.error.unwrap().code, -32600);
        assert!(adapter.security_audit().events().iter().any(|event| {
            event.action == SecurityAuditAction::ValidationRejected
                && event.reason == "invalid_request"
                && event.method.as_deref() == Some("tools/list")
                && event.request_id.as_deref() == Some("10")
        }));
    }

    #[test]
    fn legacy_mcp_adapter_direct_tools_list_rejects_notifications_before_listing() {
        let mut adapter = McpAdapter::new();
        adapter.register_tool("secure", 7).unwrap();
        let mut capabilities = CapabilityManifest::new(1);
        capabilities.set_tool(7);
        let adapter = adapter.with_negotiated_capabilities(capabilities);
        let request = JsonRpcRequest::notification(
            "tools/list",
            Some(serde_json::json!({
                "token": "authorization=Bearer plain-secret"
            })),
        );

        let response = adapter.handle_tools_list(&request).unwrap();
        let parsed = JsonRpcParser::parse_response(&response).unwrap();

        assert_eq!(parsed.id, RequestId::Null);
        assert_eq!(parsed.error.unwrap().code, -32600);
        assert!(!response.contains("plain-secret"));
        assert!(!response.contains("authorization"));
        assert!(adapter.security_audit().events().iter().any(|event| {
            event.action == SecurityAuditAction::ValidationRejected
                && event.reason == "invalid_request"
                && event.method.as_deref() == Some("tools/list")
        }));

        let audit_dump = format!("{:?}", adapter.security_audit().events());
        assert!(!audit_dump.contains("plain-secret"));
        assert!(!audit_dump.contains("authorization"));
    }

    #[test]
    fn legacy_mcp_adapter_direct_tools_list_rejects_wrong_method_before_listing() {
        let mut adapter = McpAdapter::new();
        adapter.register_tool("secure", 7).unwrap();
        let mut capabilities = CapabilityManifest::new(1);
        capabilities.set_tool(7);
        let adapter = adapter.with_negotiated_capabilities(capabilities);
        let request = JsonRpcRequest::new(
            "initialize",
            Some(serde_json::json!({
                "token": "api_key=plain-secret"
            })),
            RequestId::Number(11),
        );

        let response = adapter.handle_tools_list(&request).unwrap();
        let parsed = JsonRpcParser::parse_response(&response).unwrap();

        assert_eq!(parsed.id, RequestId::Number(11));
        assert_eq!(parsed.error.unwrap().code, -32600);
        assert!(!response.contains("plain-secret"));
        assert!(!response.contains("api_key"));
        assert!(adapter.security_audit().events().iter().any(|event| {
            event.action == SecurityAuditAction::ValidationRejected
                && event.reason == "invalid_request"
                && event.method.as_deref() == Some("initialize")
                && event.request_id.as_deref() == Some("11")
        }));

        let audit_dump = format!("{:?}", adapter.security_audit().events());
        assert!(!audit_dump.contains("plain-secret"));
        assert!(!audit_dump.contains("api_key"));
    }

    #[test]
    fn legacy_mcp_adapter_direct_tools_call_rejects_notifications_before_dispatch() {
        let calls = Arc::new(AtomicUsize::new(0));
        let router = router_with_counting_tool(Arc::clone(&calls));
        let mut adapter = McpAdapter::new();
        adapter.register_tool("secure", 7).unwrap();
        let mut capabilities = CapabilityManifest::new(1);
        capabilities.set_tool(7);
        let adapter = adapter.with_negotiated_capabilities(capabilities);
        let request = JsonRpcRequest::notification(
            "tools/call",
            Some(serde_json::json!({
                "name": "secure",
                "arguments": {"token": "api_key=plain-secret"}
            })),
        );

        let response = adapter.handle_tools_call(&request, &router).unwrap();
        let parsed = JsonRpcParser::parse_response(&response).unwrap();

        assert_eq!(parsed.id, RequestId::Null);
        assert_eq!(parsed.error.unwrap().code, -32600);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(!response.contains("plain-secret"));
        assert!(!response.contains("api_key"));
        assert!(adapter.security_audit().events().iter().any(|event| {
            event.action == SecurityAuditAction::ValidationRejected
                && event.reason == "invalid_request"
                && event.method.as_deref() == Some("tools/call")
        }));

        let audit_dump = format!("{:?}", adapter.security_audit().events());
        assert!(!audit_dump.contains("plain-secret"));
        assert!(!audit_dump.contains("api_key"));
    }

    #[test]
    fn legacy_mcp_adapter_direct_tools_call_rejects_wrong_method_before_dispatch() {
        let calls = Arc::new(AtomicUsize::new(0));
        let router = router_with_counting_tool(Arc::clone(&calls));
        let mut adapter = McpAdapter::new();
        adapter.register_tool("secure", 7).unwrap();
        let mut capabilities = CapabilityManifest::new(1);
        capabilities.set_tool(7);
        let adapter = adapter.with_negotiated_capabilities(capabilities);
        let request = JsonRpcRequest::new(
            "resources/read",
            Some(serde_json::json!({
                "name": "secure",
                "arguments": {"token": "authorization=Bearer plain-secret"}
            })),
            RequestId::Number(6),
        );

        let response = adapter.handle_tools_call(&request, &router).unwrap();
        let parsed = JsonRpcParser::parse_response(&response).unwrap();

        assert_eq!(parsed.id, RequestId::Number(6));
        assert_eq!(parsed.error.unwrap().code, -32600);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(!response.contains("plain-secret"));
        assert!(!response.contains("authorization"));
        assert!(adapter.security_audit().events().iter().any(|event| {
            event.action == SecurityAuditAction::ValidationRejected
                && event.reason == "invalid_request"
                && event.method.as_deref() == Some("resources/read")
                && event.request_id.as_deref() == Some("6")
        }));

        let audit_dump = format!("{:?}", adapter.security_audit().events());
        assert!(!audit_dump.contains("plain-secret"));
        assert!(!audit_dump.contains("authorization"));
    }
}

/// Strategy to generate a request ID
fn arb_request_id() -> impl Strategy<Value = RequestId> {
    prop_oneof![
        any::<i64>().prop_map(RequestId::Number),
        "[a-zA-Z0-9-]{1,20}".prop_map(RequestId::String),
    ]
}

/// Strategy to generate simple JSON params
fn arb_params() -> impl Strategy<Value = Option<Value>> {
    prop_oneof![
        Just(None),
        Just(Some(serde_json::json!({}))),
        "[a-z]{1,10}".prop_map(|s| Some(serde_json::json!({"key": s}))),
        any::<i32>().prop_map(|n| Some(serde_json::json!({"number": n}))),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Feature: dcp-protocol, Property 14: MCP Translation Round-Trip
    /// For any valid JSON-RPC request, formatting and parsing SHALL preserve
    /// the semantic meaning.
    /// **Validates: Requirements 11.1, 11.3**
    #[test]
    fn prop_request_round_trip(
        method in arb_method(),
        params in arb_params(),
        id in arb_request_id(),
    ) {
        let original = JsonRpcRequest::new(method.clone(), params.clone(), id.clone());

        // Format to JSON
        let json = JsonRpcParser::format_request(&original).unwrap();

        // Parse back
        let parsed = JsonRpcParser::parse_request(&json).unwrap();

        // Verify semantic equivalence
        prop_assert_eq!(parsed.jsonrpc, "2.0");
        prop_assert_eq!(parsed.method, method);
        prop_assert_eq!(parsed.id, id);
        prop_assert_eq!(parsed.params, params);
    }

    /// Feature: dcp-protocol, Property 14: MCP Translation Round-Trip
    /// For any valid JSON-RPC success response, formatting and parsing SHALL
    /// preserve the result.
    /// **Validates: Requirements 11.3, 11.4**
    #[test]
    fn prop_success_response_round_trip(
        id in arb_request_id(),
        result_key in "[a-z]{1,10}",
        result_value in "[a-z]{1,20}",
    ) {
        let result = serde_json::json!({result_key: result_value});
        let original = JsonRpcResponse::success(id.clone(), result.clone());

        // Format to JSON
        let json = JsonRpcParser::format_response(&original).unwrap();

        // Parse back
        let parsed = JsonRpcParser::parse_response(&json).unwrap();

        // Verify semantic equivalence
        prop_assert!(parsed.is_success());
        prop_assert_eq!(parsed.id, id);
        prop_assert_eq!(parsed.result, Some(result));
    }

    /// Feature: dcp-protocol, Property 14: MCP Translation Round-Trip
    /// For any valid JSON-RPC error response, formatting and parsing SHALL
    /// preserve the error.
    /// **Validates: Requirements 11.3, 11.4**
    #[test]
    fn prop_error_response_round_trip(
        id in arb_request_id(),
        code in -32700i32..0,
        message in "[a-zA-Z ]{1,50}",
    ) {
        let error = JsonRpcError::new(code, message.clone());
        let original = JsonRpcResponse::error(id.clone(), error.clone());

        // Format to JSON
        let json = JsonRpcParser::format_response(&original).unwrap();

        // Parse back
        let parsed = JsonRpcParser::parse_response(&json).unwrap();

        // Verify semantic equivalence
        prop_assert!(parsed.is_error());
        prop_assert_eq!(parsed.id, id);
        let parsed_error = parsed.error.unwrap();
        prop_assert_eq!(parsed_error.code, code);
        prop_assert_eq!(parsed_error.message, message);
    }

    /// Feature: dcp-protocol, Property 14: MCP Translation Round-Trip
    /// For any tool registration, name resolution SHALL be bidirectional.
    /// **Validates: Requirements 11.4**
    #[test]
    fn prop_tool_name_resolution_bidirectional(
        tool_name in "[a-z_]{1,20}",
        tool_id in 1u16..CapabilityManifest::MAX_TOOLS as u16,
    ) {
        let mut adapter = McpAdapter::new();
        adapter.register_tool(tool_name.clone(), tool_id).unwrap();

        // Name -> ID -> Name should be consistent
        let resolved_id = adapter.resolve_tool_name(&tool_name);
        prop_assert_eq!(resolved_id, Some(tool_id));

        let resolved_name = adapter.resolve_tool_id(tool_id);
        prop_assert_eq!(resolved_name, Some(tool_name.as_str()));
    }

    /// Feature: dcp-protocol, Property 14: MCP Translation Round-Trip
    /// For any params, translation to bytes and back SHALL preserve content.
    /// **Validates: Requirements 11.1, 11.3**
    #[test]
    fn prop_params_translation_preserves_content(
        key in "[a-z]{1,10}",
        value in "[a-zA-Z0-9]{1,20}",
    ) {
        let adapter = McpAdapter::new();
        let params = Some(serde_json::json!({key.clone(): value.clone()}));

        // Translate to bytes
        let bytes = adapter.translate_params(&params);

        // Parse bytes back as JSON
        let parsed: Value = serde_json::from_slice(&bytes).unwrap();

        // Verify content preserved
        prop_assert_eq!(parsed[&key].as_str(), Some(value.as_str()));
    }

    /// Feature: dcp-protocol, Property 14: MCP Translation Round-Trip
    /// For any ToolResult::Success with text, translation SHALL produce valid JSON.
    /// **Validates: Requirements 11.3, 11.4**
    #[test]
    fn prop_result_translation_success(
        content in "[a-zA-Z ]{1,50}",  // Only letters and spaces to avoid JSON parsing
    ) {
        let adapter = McpAdapter::new();
        let result = ToolResult::Success(content.as_bytes().to_vec());

        let value = adapter.translate_result(&result);

        // Should be a string containing the content
        prop_assert_eq!(value.as_str(), Some(content.as_str()));
    }

    /// Feature: dcp-protocol, Property 14: MCP Translation Round-Trip
    /// For any ToolResult::Success with JSON, translation SHALL preserve structure.
    /// **Validates: Requirements 11.3, 11.4**
    #[test]
    fn prop_result_translation_json(
        key in "[a-z]{1,10}",
        value in "[a-zA-Z0-9]{1,20}",
    ) {
        let adapter = McpAdapter::new();
        let json_content = serde_json::json!({key.clone(): value.clone()});
        let bytes = serde_json::to_vec(&json_content).unwrap();
        let result = ToolResult::Success(bytes);

        let translated = adapter.translate_result(&result);

        // Should preserve JSON structure
        prop_assert_eq!(translated[&key].as_str(), Some(value.as_str()));
    }

    /// Feature: dcp-protocol, Property 14: MCP Translation Round-Trip
    /// For any ToolResult::Error, translation SHALL include error info.
    /// **Validates: Requirements 11.3, 11.4**
    #[test]
    fn prop_result_translation_error(
        error_variant in 1u8..12,
    ) {
        let adapter = McpAdapter::new();
        let dcp_error = match error_variant {
            1 => DCPError::InsufficientData,
            2 => DCPError::InvalidMagic,
            3 => DCPError::UnknownMessageType,
            4 => DCPError::ToolNotFound,
            5 => DCPError::ValidationFailed,
            6 => DCPError::HashMismatch,
            7 => DCPError::SignatureInvalid,
            8 => DCPError::NonceReused,
            9 => DCPError::TimestampExpired,
            10 => DCPError::ChecksumMismatch,
            11 => DCPError::Backpressure,
            _ => DCPError::OutOfBounds,
        };

        let result = ToolResult::Error(dcp_error);
        let value = adapter.translate_result(&result);

        // Should have error structure
        prop_assert!(value["error"].is_object());
        prop_assert!(value["error"]["code"].is_number());
        prop_assert!(value["error"]["message"].is_string());
    }

    /// Feature: dcp-protocol, Property 14: MCP Translation Round-Trip
    /// For any notification (no id), parsing SHALL recognize it as notification.
    /// **Validates: Requirements 11.1**
    #[test]
    fn prop_notification_detection(
        method in arb_method(),
        params in arb_params(),
    ) {
        let notification = JsonRpcRequest::notification(method, params);

        prop_assert!(notification.is_notification());

        let json = JsonRpcParser::format_request(&notification).unwrap();
        let parsed = JsonRpcParser::parse_request(&json).unwrap();

        prop_assert!(parsed.is_notification());
    }

    /// Feature: dcp-protocol, Property 14: MCP Translation Round-Trip
    /// Multiple tool registrations SHALL be independent.
    /// **Validates: Requirements 11.4**
    #[test]
    fn prop_multiple_tool_registrations(
        tools in prop::collection::vec(
            ("[a-z_]{1,10}", 1u16..1000),
            1..20
        ),
    ) {
        let mut adapter = McpAdapter::new();

        // Deduplicate by name and id
        let mut seen_names = std::collections::HashSet::new();
        let mut seen_ids = std::collections::HashSet::new();
        let unique_tools: Vec<_> = tools.into_iter()
            .filter(|(name, id)| seen_names.insert(name.clone()) && seen_ids.insert(*id))
            .collect();

        // Register all tools
        for (name, id) in &unique_tools {
            adapter.register_tool(name.clone(), *id).unwrap();
        }

        // Verify all registrations
        for (name, id) in &unique_tools {
            prop_assert_eq!(adapter.resolve_tool_name(name), Some(*id));
            prop_assert_eq!(adapter.resolve_tool_id(*id), Some(name.as_str()));
        }

        prop_assert_eq!(adapter.tool_count(), unique_tools.len());
    }
}
