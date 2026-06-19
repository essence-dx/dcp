//! Property-based tests for MCP adapter and protocol support.
//!
//! Tests for resource routing, prompt substitution, and protocol compliance.

use proptest::prelude::*;
use std::collections::HashMap;

use dcp::binary::ArgType;
use dcp::compat::{
    json_rpc::{JsonRpcRequest, RequestId},
    CompleteAdapterError, CompleteMcpAdapter, JsonRpcError, JsonRpcParser, McpAdapter,
    PromptTemplate, ResourceTemplate, Root,
};
use dcp::dispatch::BinaryTrieRouter;
use dcp::dispatch::{SharedArgs, ToolHandler, ToolResult};
use dcp::protocol::{FieldDef, InputSchema, ToolSchema};
use dcp::resource::{
    uri_matches_template, MemoryResourceHandler, ResourceContent, ResourceError, ResourceRegistry,
};
use dcp::security::{SecurityAuditAction, REDACTED};
use dcp::{CapabilityManifest, DCPError};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

// ============================================================================
// Property 8: Resource URI Routing
// **Validates: Requirements 4.1, 4.2**
// For any registered resource handler with URI template, and any URI matching
// that template, the server SHALL route the request to the correct handler.
// ============================================================================

fn arb_uri_template() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("file:///{path}".to_string()),
        Just("http://example.com/{resource}".to_string()),
        Just("db:///{table}/{id}".to_string()),
        Just("custom://{type}/{name}".to_string()),
    ]
}

fn arb_matching_uri(template: &str) -> impl Strategy<Value = String> {
    // Generate URIs that match the template
    let prefix = template.split('{').next().unwrap_or("").to_string();
    prop::string::string_regex(&format!("{}[a-z0-9/]+", regex::escape(&prefix)))
        .unwrap()
        .prop_map(|s| s.chars().take(100).collect())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Feature: dcp-production, Property 8: Resource URI Routing
    /// For any URI template and matching URI, the handler should be found.
    #[test]
    fn prop_resource_uri_routing(
        template_idx in 0usize..3,
        suffix in "[a-z0-9]{1,20}"
    ) {
        let templates = [
            "file:///{path}",
            "http://example.com/{resource}",
            "custom://{name}",
        ];
        let template = templates[template_idx];
        let prefix = template.split('{').next().unwrap_or("");
        let uri = format!("{}{}", prefix, suffix);

        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut registry = ResourceRegistry::new();
            let mut handler = MemoryResourceHandler::new(template);
            handler.add_resource(&uri, ResourceContent::text(&uri, "text/plain", "content"));
            registry.register(handler).unwrap();

            // Should find handler
            let found = registry.match_uri(&uri);
            prop_assert!(found.is_some(), "Should find handler for URI: {}", uri);

            // Should read content
            let content = registry.read(&uri);
            prop_assert!(content.is_ok(), "Should read content for URI: {}", uri);

            Ok(())
        })?;
    }

    /// Feature: dcp-production, Property 8: Resource URI Routing (non-matching)
    /// For URIs that don't match any template, no handler should be found.
    #[test]
    fn prop_resource_uri_routing_no_match(
        uri in "ftp://[a-z]{1,10}/[a-z]{1,10}"
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut registry = ResourceRegistry::new();
            let handler = MemoryResourceHandler::new("file:///{path}");
            registry.register(handler).unwrap();

            // Should not find handler for non-matching URI
            let found = registry.match_uri(&uri);
            prop_assert!(found.is_none(), "Should not find handler for non-matching URI: {}", uri);

            Ok(())
        })?;
    }
}

// ============================================================================
// Property 11: Prompt Parameter Substitution
// **Validates: Requirements 5.2**
// For any prompt template with placeholders and valid arguments, rendering
// the prompt SHALL substitute all placeholders with their corresponding values.
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Feature: dcp-production, Property 11: Prompt Parameter Substitution
    /// For any template and arguments, all placeholders should be substituted.
    #[test]
    fn prop_prompt_parameter_substitution(
        name in "[a-z]{1,10}",
        value in "[a-zA-Z0-9 ]{1,50}"
    ) {
        let template = PromptTemplate::new(
            "test",
            "Test prompt",
            format!("Hello {{{{{}}}}}!", name)
        ).with_argument(&name, "Test arg", true);

        let mut args = HashMap::new();
        args.insert(name.clone(), value.clone());

        let rendered = template.render(&args).unwrap();

        // Should contain the value
        prop_assert!(rendered.contains(&value),
            "Rendered template should contain value '{}', got: {}", value, rendered);

        // Should not contain the placeholder
        let placeholder = format!("{{{{{}}}}}", name);
        prop_assert!(!rendered.contains(&placeholder),
            "Rendered template should not contain placeholder '{}'", placeholder);
    }

    /// Feature: dcp-production, Property 11: Multiple parameters
    /// Multiple placeholders should all be substituted.
    #[test]
    fn prop_prompt_multiple_parameters(
        values in prop::collection::vec("[a-zA-Z0-9]{1,10}", 1..5)
    ) {
        let mut template_str = String::new();
        let mut template = PromptTemplate::new("test", "Test", "");
        let mut args = HashMap::new();

        for (i, value) in values.iter().enumerate() {
            let name = format!("arg{}", i);
            template_str.push_str(&format!("{{{{{}}}}} ", name));
            template = template.with_argument(&name, "Arg", true);
            args.insert(name, value.clone());
        }

        template.template = template_str;
        let rendered = template.render(&args).unwrap();

        // All values should be present
        for value in &values {
            prop_assert!(rendered.contains(value),
                "Rendered should contain '{}'", value);
        }
    }
}

// ============================================================================
// Property 12: Prompt Validation
// **Validates: Requirements 5.3, 5.4, 5.5**
// For any prompt template with required parameters, a request missing any
// required parameter SHALL return a validation error.
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Feature: dcp-production, Property 12: Prompt Validation (missing required)
    /// Missing required arguments should cause an error.
    #[test]
    fn prop_prompt_validation_missing_required(
        required_args in prop::collection::vec("[a-z]{1,10}", 1..5)
    ) {
        let mut template = PromptTemplate::new("test", "Test", "template");
        for arg in &required_args {
            template = template.with_argument(arg, "Required arg", true);
        }

        // Empty args should fail
        let args = HashMap::new();
        let result = template.render(&args);
        prop_assert!(result.is_err(), "Should fail with missing required args");
    }

    /// Feature: dcp-production, Property 12: Prompt Validation (optional ok)
    /// Optional arguments can be omitted without error.
    #[test]
    fn prop_prompt_validation_optional_ok(
        optional_args in prop::collection::vec("[a-z]{1,10}", 1..5)
    ) {
        let mut template = PromptTemplate::new("test", "Test", "template");
        for arg in &optional_args {
            template = template.with_argument(arg, "Optional arg", false);
        }

        // Empty args should succeed for optional
        let args = HashMap::new();
        let result = template.render(&args);
        prop_assert!(result.is_ok(), "Should succeed with missing optional args");
    }
}

// ============================================================================
// Property 6: Unknown Method Error
// **Validates: Requirements 3.8**
// For any JSON-RPC request with a method name not in the supported set,
// the server SHALL return error code -32601 (Method not found).
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Feature: dcp-production, Property 6: Unknown Method Error
    /// Unknown methods should return -32601.
    #[test]
    fn prop_unknown_method_error(
        method in "unknown/[a-z]{1,20}"
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let adapter = CompleteMcpAdapter::new();
            let router = BinaryTrieRouter::new();

            let json = format!(r#"{{"jsonrpc":"2.0","method":"{}","id":1}}"#, method);
            let result = adapter.handle_request(&json, &router).await.unwrap();

            prop_assert!(result.is_some(), "Should return response for unknown method");

            let response = JsonRpcParser::parse_response(&result.unwrap()).unwrap();
            prop_assert!(response.is_error(), "Should be error response");
            prop_assert_eq!(response.error.unwrap().code, -32601,
                "Should return -32601 for unknown method");

            Ok(())
        })?;
    }
}

// ============================================================================
// Property 7: Notification No-Response
// **Validates: Requirements 3.9**
// For any valid JSON-RPC notification (request without `id` field),
// the server SHALL process it without sending any response.
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Feature: dcp-production, Property 7: Notification No-Response
    /// Notifications should not produce a response.
    #[test]
    fn prop_notification_no_response(
        _dummy in 0..10i32
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let adapter = CompleteMcpAdapter::new();
            let router = BinaryTrieRouter::new();

            // Notification has no id
            let json = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
            let result = adapter.handle_request(json, &router).await.unwrap();

            prop_assert!(result.is_none(), "Notification should not produce response");

            Ok(())
        })?;
    }
}

#[tokio::test]
async fn complete_adapter_accepts_spec_initialized_notification_without_method_error_audit() {
    let adapter = CompleteMcpAdapter::new();
    let router = BinaryTrieRouter::new();

    adapter
        .handle_request(r#"{"jsonrpc":"2.0","method":"initialize","id":1}"#, &router)
        .await
        .unwrap();

    let response = adapter
        .handle_request(
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            &router,
        )
        .await
        .unwrap();

    assert!(response.is_none());
    assert!(!adapter.security_audit().events().iter().any(|event| {
        event.reason == "method_not_found"
            && event.method.as_deref() == Some("notifications/initialized")
    }));
}

#[tokio::test]
async fn complete_adapter_rejects_legacy_initialized_alias_without_completing_lifecycle() {
    let adapter = CompleteMcpAdapter::new();
    let router = BinaryTrieRouter::new();

    adapter
        .handle_request(r#"{"jsonrpc":"2.0","method":"initialize","id":1}"#, &router)
        .await
        .unwrap();

    let alias_response = adapter
        .handle_request(r#"{"jsonrpc":"2.0","method":"initialized"}"#, &router)
        .await
        .unwrap();

    assert!(alias_response.is_none());
    assert!(adapter.security_audit().events().iter().any(|event| {
        event.reason == "notification_not_allowed" && event.method.as_deref() == Some("initialized")
    }));

    let spec_response = adapter
        .handle_request(
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            &router,
        )
        .await
        .unwrap();

    assert!(spec_response.is_none());
    assert!(!adapter.security_audit().events().iter().any(|event| {
        event.reason == "lifecycle_already_initialized"
            && event.method.as_deref() == Some("notifications/initialized")
    }));
}

#[tokio::test]
async fn complete_adapter_direct_initialized_rejects_request_with_id() {
    let adapter = CompleteMcpAdapter::new();
    let router = BinaryTrieRouter::new();

    adapter
        .handle_request(r#"{"jsonrpc":"2.0","method":"initialize","id":1}"#, &router)
        .await
        .unwrap();

    let request = JsonRpcParser::parse_request(
        r#"{"jsonrpc":"2.0","method":"notifications/initialized","id":2}"#,
    )
    .unwrap();
    let result = adapter.handle_initialized(&request).await;

    assert!(matches!(
        result,
        Err(CompleteAdapterError::InvalidRequest(_))
    ));

    let spec_response = adapter
        .handle_request(
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            &router,
        )
        .await
        .unwrap();

    assert!(spec_response.is_none());
    assert!(!adapter.security_audit().events().iter().any(|event| {
        event.reason == "lifecycle_already_initialized"
            && event.method.as_deref() == Some("notifications/initialized")
    }));
}

#[tokio::test]
async fn complete_adapter_rejects_initialized_with_params_without_completing_lifecycle() {
    let adapter = CompleteMcpAdapter::new();
    let router = BinaryTrieRouter::new();

    adapter
        .handle_request(r#"{"jsonrpc":"2.0","method":"initialize","id":1}"#, &router)
        .await
        .unwrap();

    let response = adapter
        .handle_request(
            r#"{"jsonrpc":"2.0","method":"notifications/initialized","params":{"api_key":"plain-secret"}}"#,
            &router,
        )
        .await
        .unwrap();

    assert!(response.is_none());
    assert!(adapter.security_audit().events().iter().any(|event| {
        event.reason == "invalid_params"
            && event.method.as_deref() == Some("notifications/initialized")
            && !event.to_json().contains("plain-secret")
            && !event.to_json().contains("api_key")
    }));

    let list_response = adapter
        .handle_request(r#"{"jsonrpc":"2.0","method":"tools/list","id":2}"#, &router)
        .await
        .unwrap()
        .unwrap();
    let parsed = JsonRpcParser::parse_response(&list_response).unwrap();

    assert_eq!(parsed.error.unwrap().code, -32600);
    assert!(adapter.security_audit().events().iter().any(|event| {
        event.reason == "lifecycle_not_initialized" && event.method.as_deref() == Some("tools/list")
    }));
}

async fn send_initialized(adapter: &CompleteMcpAdapter, router: &BinaryTrieRouter) {
    let response = adapter
        .handle_request(
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            router,
        )
        .await
        .unwrap();

    assert!(response.is_none());
}

async fn initialize_and_send_initialized(
    adapter: &CompleteMcpAdapter,
    router: &BinaryTrieRouter,
    request: &str,
) -> Option<String> {
    let response = adapter.handle_request(request, router).await.unwrap();
    send_initialized(adapter, router).await;
    response
}

#[tokio::test]
async fn complete_adapter_rejects_initialized_before_initialize_with_audit() {
    let adapter = CompleteMcpAdapter::new();
    let router = BinaryTrieRouter::new();

    let response = adapter
        .handle_request(
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            &router,
        )
        .await
        .unwrap();

    assert!(response.is_none());
    assert!(adapter.security_audit().events().iter().any(|event| {
        event.reason == "lifecycle_not_initialized"
            && event.method.as_deref() == Some("notifications/initialized")
    }));
}

#[tokio::test]
async fn complete_adapter_rejects_duplicate_initialized_with_audit() {
    let adapter = CompleteMcpAdapter::new();
    let router = BinaryTrieRouter::new();

    adapter
        .handle_request(r#"{"jsonrpc":"2.0","method":"initialize","id":1}"#, &router)
        .await
        .unwrap();
    adapter
        .handle_request(
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            &router,
        )
        .await
        .unwrap();

    let duplicate = adapter
        .handle_request(
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            &router,
        )
        .await
        .unwrap();

    assert!(duplicate.is_none());
    assert!(adapter.security_audit().events().iter().any(|event| {
        event.reason == "lifecycle_already_initialized"
            && event.method.as_deref() == Some("notifications/initialized")
    }));
}

#[tokio::test]
async fn complete_adapter_rejects_unknown_notification_method_before_dispatch() {
    let adapter = CompleteMcpAdapter::new();
    let router = BinaryTrieRouter::new();

    let response = adapter
        .handle_request(
            r#"{"jsonrpc":"2.0","method":"notifications/not-real"}"#,
            &router,
        )
        .await
        .unwrap();

    assert!(response.is_none());
    assert!(adapter.security_audit().events().iter().any(|event| {
        event.reason == "notification_not_allowed"
            && event.method.as_deref() == Some("notifications/not-real")
    }));
}

#[tokio::test]
async fn complete_adapter_rejects_remote_shutdown_abuse_with_audit() {
    let adapter = CompleteMcpAdapter::new();
    let router = BinaryTrieRouter::new();

    let attempts = [
        r#"{"jsonrpc":"2.0","method":"shutdown","id":1}"#,
        r#"{"jsonrpc":"2.0","method":"exit","id":2}"#,
        r#"{"jsonrpc":"2.0","method":"terminate","id":3}"#,
        r#"{"jsonrpc":"2.0","method":"server/shutdown","id":4}"#,
        r#"{"jsonrpc":"2.0","method":"notifications/shutdown"}"#,
    ];

    for request in attempts {
        let response = adapter.handle_request(request, &router).await.unwrap();

        if response.is_some() {
            let response = response.unwrap();
            let parsed = JsonRpcParser::parse_response(&response).unwrap();

            assert!(parsed.is_error());
            assert_eq!(parsed.error.unwrap().code, -32601);
        }
    }

    let events = adapter.security_audit().events();
    for method in [
        "shutdown",
        "exit",
        "terminate",
        "server/shutdown",
        "notifications/shutdown",
    ] {
        assert!(
            events.iter().any(|event| {
                event.action == SecurityAuditAction::ShutdownRejected
                    && event.reason == "remote_shutdown_rejected"
                    && event.method.as_deref() == Some(method)
            }),
            "missing shutdown rejection audit for {method}"
        );
    }
}

#[tokio::test]
async fn complete_adapter_rejects_client_originated_sampling_before_validation() {
    let adapter = CompleteMcpAdapter::new();
    let router = BinaryTrieRouter::new();

    initialize_and_send_initialized(
        &adapter,
        &router,
        r#"{"jsonrpc":"2.0","method":"initialize","id":1}"#,
    )
    .await
    .unwrap();

    let malformed_requests = [
        r#"{"jsonrpc":"2.0","method":"sampling/createMessage","id":1}"#,
        r#"{"jsonrpc":"2.0","method":"sampling/createMessage","params":[],"id":2}"#,
        r#"{"jsonrpc":"2.0","method":"sampling/createMessage","params":{"messages":"nope"},"id":3}"#,
        r#"{"jsonrpc":"2.0","method":"sampling/createMessage","params":{"messages":[{"role":"root","content":{"type":"text","text":"hi"}}]},"id":4}"#,
        r#"{"jsonrpc":"2.0","method":"sampling/createMessage","params":{"messages":[{"role":"user","content":{"type":"text","text":42}}]},"id":5}"#,
        r#"{"jsonrpc":"2.0","method":"sampling/createMessage","params":{"messages":[{"role":"user","content":{"type":"text","text":"hi"}}],"maxTokens":0},"id":6}"#,
    ];

    for request in malformed_requests {
        let response = adapter
            .handle_request(request, &router)
            .await
            .unwrap()
            .unwrap();
        let parsed = JsonRpcParser::parse_response(&response).unwrap();

        assert!(parsed.is_error());
        assert_eq!(parsed.error.unwrap().code, -32601);
        assert!(!response.contains("hello"));
    }
}

#[tokio::test]
async fn complete_adapter_rejects_minimal_client_originated_sampling_request() {
    let adapter = CompleteMcpAdapter::new();
    let router = BinaryTrieRouter::new();

    initialize_and_send_initialized(
        &adapter,
        &router,
        r#"{"jsonrpc":"2.0","method":"initialize","id":1}"#,
    )
    .await
    .unwrap();

    let response = adapter
        .handle_request(
            r#"{"jsonrpc":"2.0","method":"sampling/createMessage","params":{"messages":[{"role":"user","content":{"type":"text","text":"hello"}}],"maxTokens":64},"id":1}"#,
            &router,
        )
        .await
        .unwrap()
        .unwrap();
    let parsed = JsonRpcParser::parse_response(&response).unwrap();

    assert!(parsed.is_error());
    assert_eq!(parsed.error.unwrap().code, -32601);
}

// ============================================================================
// URI Template Matching Properties
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// URI template matching is consistent.
    #[test]
    fn prop_uri_template_matching_consistent(
        prefix in "[a-z]{3,10}://",
        suffix in "[a-z0-9/]{1,20}"
    ) {
        let template = format!("{}{{param}}", prefix);
        let uri = format!("{}{}", prefix, suffix);

        let matches = uri_matches_template(&uri, &template);

        // If prefix matches, should match
        if uri.starts_with(&prefix) {
            prop_assert!(matches, "URI {} should match template {}", uri, template);
        }
    }
}

#[test]
fn uri_template_literal_suffixes_must_match_to_end() {
    assert!(uri_matches_template(
        "file:///allowed/readme.md",
        "file:///{path}"
    ));
    assert!(uri_matches_template(
        "file:///allowed/readme.md",
        "file:///{path}.md"
    ));
    assert!(!uri_matches_template(
        "file:///allowed/readme.md.evil",
        "file:///{path}.md"
    ));
    assert!(!uri_matches_template(
        "file:///allowed.txt.evil",
        "file:///allowed.txt"
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    struct CountingTool {
        calls: Arc<AtomicUsize>,
    }

    struct RequiredBoolTool {
        calls: Arc<AtomicUsize>,
        schema: ToolSchema,
    }

    impl RequiredBoolTool {
        fn new(calls: Arc<AtomicUsize>) -> Self {
            let mut input = InputSchema::new();
            input.add_field(FieldDef::new("enabled", ArgType::Bool, 0, 1));
            input.set_required(0);

            Self {
                calls,
                schema: ToolSchema {
                    name: "typed",
                    id: 7,
                    description: "typed tool",
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
                name: "secret",
                id: 7,
                description: "secret tool",
                input: InputSchema {
                    required: 0,
                    fields: Vec::new(),
                },
            };
            &SCHEMA
        }
    }

    impl ToolHandler for RequiredBoolTool {
        fn execute(&self, args: &SharedArgs) -> Result<ToolResult, DCPError> {
            if !args.read_bool_at(0)? {
                return Err(DCPError::ValidationFailed);
            }

            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(ToolResult::success(br#"{"accepted":true}"#.to_vec()))
        }

        fn schema(&self) -> &ToolSchema {
            &self.schema
        }
    }

    #[tokio::test]
    async fn complete_adapter_rejects_normal_requests_until_initialized() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut adapter = CompleteMcpAdapter::new();
        adapter.register_tool("secret", 7).unwrap();

        let mut router = BinaryTrieRouter::new();
        router
            .register(Box::new(CountingTool {
                calls: Arc::clone(&calls),
            }))
            .unwrap();

        let pre_initialize_requests = [
            (
                "tools/list",
                r#"{"jsonrpc":"2.0","method":"tools/list","id":10}"#,
            ),
            (
                "tools/call",
                r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"secret"},"id":11}"#,
            ),
            (
                "resources/read",
                r#"{"jsonrpc":"2.0","method":"resources/read","params":{"uri":"file:///secret.txt"},"id":12}"#,
            ),
            (
                "resources/list",
                r#"{"jsonrpc":"2.0","method":"resources/list","id":13}"#,
            ),
            (
                "resources/subscribe",
                r#"{"jsonrpc":"2.0","method":"resources/subscribe","params":{"uri":"file:///secret.txt"},"id":14}"#,
            ),
            (
                "resources/unsubscribe",
                r#"{"jsonrpc":"2.0","method":"resources/unsubscribe","params":{"uri":"file:///secret.txt"},"id":15}"#,
            ),
            (
                "prompts/list",
                r#"{"jsonrpc":"2.0","method":"prompts/list","id":16}"#,
            ),
            (
                "prompts/get",
                r#"{"jsonrpc":"2.0","method":"prompts/get","params":{"name":"secret"},"id":17}"#,
            ),
            (
                "logging/setLevel",
                r#"{"jsonrpc":"2.0","method":"logging/setLevel","params":{"level":"info"},"id":18}"#,
            ),
            (
                "sampling/createMessage",
                r#"{"jsonrpc":"2.0","method":"sampling/createMessage","params":{"messages":[{"role":"user","content":{"type":"text","text":"hello"}}],"maxTokens":64},"id":19}"#,
            ),
            (
                "completion/complete",
                r#"{"jsonrpc":"2.0","method":"completion/complete","id":20}"#,
            ),
            (
                "roots/list",
                r#"{"jsonrpc":"2.0","method":"roots/list","id":21}"#,
            ),
            (
                "elicitation/create",
                r#"{"jsonrpc":"2.0","method":"elicitation/create","id":22}"#,
            ),
        ];

        for (method, request) in pre_initialize_requests.iter() {
            let response = adapter
                .handle_request(request, &router)
                .await
                .unwrap()
                .unwrap();
            let parsed = JsonRpcParser::parse_response(&response).unwrap();

            assert!(parsed.is_error(), "{method} should be rejected");
            assert_eq!(parsed.error.unwrap().code, -32600);
            assert!(!response.contains("secret"));
            assert!(adapter.security_audit().events().iter().any(|event| {
                event.reason == "lifecycle_not_initialized"
                    && event.method.as_deref() == Some(method)
            }));
        }

        adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"initialize","params":{"capabilities":{"dcp":{"tools":[7]}}},"id":1}"#,
                &router,
            )
            .await
            .unwrap()
            .unwrap();

        for (method, request) in pre_initialize_requests {
            let response = adapter
                .handle_request(request, &router)
                .await
                .unwrap()
                .unwrap();
            let parsed = JsonRpcParser::parse_response(&response).unwrap();

            assert!(
                parsed.is_error(),
                "{method} should be rejected before initialized"
            );
            assert_eq!(parsed.error.unwrap().code, -32600);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        send_initialized(&adapter, &router).await;

        let ready_call = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"secret"},"id":20}"#,
                &router,
            )
            .await
            .unwrap()
            .unwrap();
        let ready_call = JsonRpcParser::parse_response(&ready_call).unwrap();

        assert!(ready_call.is_success());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn complete_adapter_direct_handlers_reject_until_initialized() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut adapter = CompleteMcpAdapter::new();
        adapter.register_tool("secret", 7).unwrap();
        adapter
            .register_prompt(PromptTemplate::new("secret", "secret prompt", "secret"))
            .unwrap();

        let mut router = BinaryTrieRouter::new();
        router
            .register(Box::new(CountingTool {
                calls: Arc::clone(&calls),
            }))
            .unwrap();

        let mut resource = MemoryResourceHandler::new("file:///{path}");
        resource.add_resource(
            "file:///secret.txt",
            ResourceContent::text("file:///secret.txt", "text/plain", "secret"),
        );
        adapter
            .resources()
            .write()
            .await
            .register(resource)
            .unwrap();
        adapter.roots().add_root(Root::new("file:///")).await;

        adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{"dcp":{"tools":[7],"resources":[0],"prompts":[0]}}},"id":1}"#,
                &router,
            )
            .await
            .unwrap()
            .unwrap();

        let tool_request = JsonRpcParser::parse_request(
            r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"secret"},"id":2}"#,
        )
        .unwrap();
        let resource_request = JsonRpcParser::parse_request(
            r#"{"jsonrpc":"2.0","method":"resources/read","params":{"uri":"file:///secret.txt"},"id":3}"#,
        )
        .unwrap();
        let prompt_request = JsonRpcParser::parse_request(
            r#"{"jsonrpc":"2.0","method":"prompts/get","params":{"name":"secret"},"id":4}"#,
        )
        .unwrap();
        let completion_request = JsonRpcParser::parse_request(
            r#"{"jsonrpc":"2.0","method":"completion/complete","params":{"ref":{"type":"ref/prompt","name":"secret"},"argument":{"name":"topic","value":"x"}},"id":5}"#,
        )
        .unwrap();

        let tool_error = adapter
            .handle_tools_call(&tool_request, &router)
            .await
            .unwrap_err();
        let resource_error = adapter
            .handle_resources_read(&resource_request)
            .await
            .unwrap_err();
        let prompt_error = adapter
            .handle_prompts_get(&prompt_request)
            .await
            .unwrap_err();
        let completion_error = adapter
            .handle_completion_complete(&completion_request)
            .await
            .unwrap_err();

        assert!(matches!(
            tool_error,
            CompleteAdapterError::LifecycleNotInitialized
        ));
        assert!(matches!(
            resource_error,
            CompleteAdapterError::LifecycleNotInitialized
        ));
        assert!(matches!(
            prompt_error,
            CompleteAdapterError::LifecycleNotInitialized
        ));
        assert!(matches!(
            completion_error,
            CompleteAdapterError::LifecycleNotInitialized
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        send_initialized(&adapter, &router).await;
        let ready = adapter
            .handle_tools_call(&tool_request, &router)
            .await
            .unwrap();
        let ready = JsonRpcParser::parse_response(&ready).unwrap();

        assert!(ready.is_success());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn complete_adapter_rejects_client_originated_elicitation_without_pending_state() {
        let adapter = CompleteMcpAdapter::new();
        let router = BinaryTrieRouter::new();

        initialize_and_send_initialized(
            &adapter,
            &router,
            r#"{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{}},"id":1}"#,
        )
        .await;

        let response = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            adapter.handle_request(
                r#"{"jsonrpc":"2.0","method":"elicitation/create","params":{"message":"secret token"},"id":22}"#,
                &router,
            ),
        )
        .await
        .expect("client-originated elicitation/create must not wait for user input")
        .unwrap()
        .unwrap();
        let parsed = JsonRpcParser::parse_response(&response).unwrap();

        assert!(parsed.is_error());
        assert_eq!(parsed.error.unwrap().code, -32601);
        assert_eq!(adapter.elicitation().pending_count().await, 0);
        assert!(!response.contains("secret token"));
        assert!(adapter.security_audit().events().iter().any(|event| {
            event.reason == "server_to_client_method"
                && event.method.as_deref() == Some("elicitation/create")
        }));
    }

    #[tokio::test]
    async fn complete_adapter_initialize_does_not_advertise_client_capabilities_or_false_subscribe()
    {
        let adapter = CompleteMcpAdapter::new();
        let router = BinaryTrieRouter::new();
        let mut resource = MemoryResourceHandler::new("file:///{path}");
        resource.add_resource(
            "file:///allowed/readme.md",
            ResourceContent::text("file:///allowed/readme.md", "text/plain", "inside"),
        );
        adapter
            .resources()
            .write()
            .await
            .register(resource)
            .unwrap();

        let response = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{"dcp":{"resources":[0]}}},"id":1}"#,
                &router,
            )
            .await
            .unwrap()
            .unwrap();
        let parsed = JsonRpcParser::parse_response(&response).unwrap();
        let capabilities = parsed
            .result
            .as_ref()
            .and_then(|result| result.get("capabilities"))
            .and_then(|capabilities| capabilities.as_object())
            .unwrap();

        assert!(!capabilities.contains_key("roots"));
        assert!(!capabilities.contains_key("elicitation"));
        assert_ne!(
            capabilities
                .get("resources")
                .and_then(|resources| resources.get("subscribe"))
                .and_then(|subscribe| subscribe.as_bool()),
            Some(true)
        );
    }

    #[tokio::test]
    async fn complete_adapter_rejects_client_originated_roots_and_sampling_after_initialized() {
        let adapter = CompleteMcpAdapter::new();
        let router = BinaryTrieRouter::new();
        adapter.roots().add_root(Root::new("file:///secret")).await;

        initialize_and_send_initialized(
            &adapter,
            &router,
            r#"{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{}},"id":1}"#,
        )
        .await;

        let requests = [
            (
                "roots/list",
                r#"{"jsonrpc":"2.0","method":"roots/list","id":21}"#,
            ),
            (
                "sampling/createMessage",
                r#"{"jsonrpc":"2.0","method":"sampling/createMessage","params":{"messages":[{"role":"user","content":{"type":"text","text":"hello"}}],"maxTokens":64},"id":22}"#,
            ),
        ];

        for (method, request) in requests {
            let response = adapter
                .handle_request(request, &router)
                .await
                .unwrap()
                .unwrap();
            let parsed = JsonRpcParser::parse_response(&response).unwrap();

            assert!(parsed.is_error(), "{method} should be rejected");
            assert_eq!(parsed.error.unwrap().code, -32601);
            assert!(!response.contains("secret"));
            assert!(adapter.security_audit().events().iter().any(|event| {
                event.reason == "server_to_client_method" && event.method.as_deref() == Some(method)
            }));
        }
    }

    #[tokio::test]
    async fn complete_adapter_rejects_non_string_protocol_version_without_consuming_initialize() {
        let adapter = CompleteMcpAdapter::new();
        let router = BinaryTrieRouter::new();

        let malformed = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":42,"capabilities":{}},"id":1}"#,
                &router,
            )
            .await
            .unwrap()
            .unwrap();
        let malformed = JsonRpcParser::parse_response(&malformed).unwrap();

        assert!(malformed.is_error());
        assert_eq!(malformed.error.unwrap().code, -32602);

        let valid = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{}},"id":2}"#,
                &router,
            )
            .await
            .unwrap()
            .unwrap();
        let valid = JsonRpcParser::parse_response(&valid).unwrap();

        assert!(valid.is_success());
    }

    #[test]
    fn jsonrpc_null_id_is_not_notification() {
        let request =
            JsonRpcParser::parse_request(r#"{"jsonrpc":"2.0","method":"ping","id":null}"#).unwrap();

        assert!(!request.is_notification());
    }

    #[test]
    fn jsonrpc_rejects_reserved_rpc_method() {
        let result =
            JsonRpcParser::parse_request(r#"{"jsonrpc":"2.0","method":"rpc.discover","id":1}"#);

        assert!(result.is_err());
    }

    #[test]
    fn jsonrpc_rejects_oversized_request_before_parse() {
        let oversized = format!(
            r#"{{"jsonrpc":"2.0","method":"ping","params":{{"blob":"{}"}},"id":1}}"#,
            "x".repeat(64)
        );

        let result = JsonRpcParser::parse_request_with_limit(&oversized, 32);

        assert!(result.is_err());
    }

    #[test]
    fn jsonrpc_rejects_response_fields_on_request() {
        let result = JsonRpcParser::parse_request(
            r#"{"jsonrpc":"2.0","method":"ping","result":{"secret":"value"},"id":1}"#,
        );

        assert!(result.is_err());
    }

    #[test]
    fn jsonrpc_rejects_scalar_params_on_request() {
        let result = JsonRpcParser::parse_request(
            r#"{"jsonrpc":"2.0","method":"ping","params":"raw","id":1}"#,
        );

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn complete_adapter_rejects_oversized_jsonrpc_before_parse() {
        let adapter = CompleteMcpAdapter::new().with_max_request_size(32);
        let router = BinaryTrieRouter::new();
        let oversized = format!(
            r#"{{"jsonrpc":"2.0","method":"ping","params":{{"blob":"{}"}},"id":1}}"#,
            "x".repeat(64)
        );

        let response = adapter
            .handle_request(&oversized, &router)
            .await
            .unwrap()
            .unwrap();
        let parsed = JsonRpcParser::parse_response(&response).unwrap();

        assert_eq!(parsed.error.unwrap().code, -32600);
        assert!(adapter
            .security_audit()
            .events()
            .iter()
            .any(|event| event.reason == "request_too_large"));
    }

    #[tokio::test]
    async fn complete_adapter_rejects_oversized_secret_bearing_request_id() {
        let adapter = CompleteMcpAdapter::new();
        let router = BinaryTrieRouter::new();
        let secret_id = format!("accessToken={}", "plain-secret".repeat(32));
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "ping",
            "id": secret_id
        })
        .to_string();

        let response = adapter
            .handle_request(&request, &router)
            .await
            .unwrap()
            .unwrap();
        let parsed = JsonRpcParser::parse_response(&response).unwrap();

        assert!(parsed.is_error());
        assert_eq!(parsed.error.unwrap().code, -32600);
        assert!(!response.contains("plain-secret"));
        assert!(!response.contains("accessToken"));
        assert!(adapter
            .security_audit()
            .events()
            .iter()
            .any(|event| event.reason == "request_id_too_large"));
    }

    #[tokio::test]
    async fn complete_adapter_rejects_short_secret_bearing_request_id() {
        let adapter = CompleteMcpAdapter::new();
        let router = BinaryTrieRouter::new();
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "unknown/method",
            "id": "access_token=plain-secret"
        })
        .to_string();

        let response = adapter
            .handle_request(&request, &router)
            .await
            .unwrap()
            .unwrap();
        let parsed = JsonRpcParser::parse_response(&response).unwrap();

        assert!(parsed.is_error());
        assert_eq!(parsed.id, RequestId::Null);
        assert_eq!(parsed.error.unwrap().code, -32600);
        assert!(!response.contains("plain-secret"));
        assert!(!response.contains("access_token"));
        assert!(adapter
            .security_audit()
            .events()
            .iter()
            .any(|event| event.reason == "request_id_sensitive"));
    }

    #[tokio::test]
    async fn complete_adapter_rejects_url_encoded_secret_bearing_request_id() {
        let adapter = CompleteMcpAdapter::new();
        let router = BinaryTrieRouter::new();
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "unknown/method",
            "id": "api%5Fkey=abc123"
        })
        .to_string();

        let response = adapter
            .handle_request(&request, &router)
            .await
            .unwrap()
            .unwrap();
        let parsed = JsonRpcParser::parse_response(&response).unwrap();
        let audit_dump = adapter
            .security_audit()
            .events()
            .iter()
            .map(|event| event.to_json())
            .collect::<Vec<_>>()
            .join("\n");

        assert!(parsed.is_error());
        assert_eq!(parsed.id, RequestId::Null);
        assert_eq!(parsed.error.unwrap().code, -32600);
        assert!(!response.contains("abc123"));
        assert!(!response.contains("api%5Fkey"));
        assert!(!audit_dump.contains("abc123"));
        assert!(!audit_dump.contains("api%5Fkey"));
        assert!(audit_dump.contains("request_id_sensitive"));
    }

    #[tokio::test]
    async fn complete_adapter_rejects_jsonrpc_batch_without_dispatch() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut adapter = CompleteMcpAdapter::new();
        adapter.register_tool("secret", 7).unwrap();

        let mut router = BinaryTrieRouter::new();
        router
            .register(Box::new(CountingTool {
                calls: Arc::clone(&calls),
            }))
            .unwrap();
        adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"initialize","params":{"capabilities":{"dcp":{"tools":[7]}}},"id":1}"#,
                &router,
            )
            .await
            .unwrap();
        send_initialized(&adapter, &router).await;

        let response = adapter
            .handle_request(
                r#"[{"jsonrpc":"2.0","method":"tools/call","params":{"name":"secret","arguments":{"api_key":"plain-secret"}},"id":2}]"#,
                &router,
            )
            .await
            .unwrap()
            .unwrap();
        let parsed = JsonRpcParser::parse_response(&response).unwrap();

        assert!(parsed.is_error());
        assert_eq!(parsed.id, RequestId::Null);
        assert_eq!(parsed.error.unwrap().code, -32600);
        assert!(!response.contains("plain-secret"));
        assert!(!response.contains("api_key"));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(adapter
            .security_audit()
            .events()
            .iter()
            .any(|event| event.reason == "batch_unsupported"));
    }

    #[tokio::test]
    async fn complete_adapter_rejects_unknown_top_level_jsonrpc_fields_without_dispatch() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut adapter = CompleteMcpAdapter::new();
        adapter.register_tool("secret", 7).unwrap();

        let mut router = BinaryTrieRouter::new();
        router
            .register(Box::new(CountingTool {
                calls: Arc::clone(&calls),
            }))
            .unwrap();
        adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"initialize","params":{"capabilities":{"dcp":{"tools":[7]}}},"id":1}"#,
                &router,
            )
            .await
            .unwrap();
        send_initialized(&adapter, &router).await;

        let response = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"secret","arguments":{}},"api_key":"plain-secret","id":2}"#,
                &router,
            )
            .await
            .unwrap()
            .unwrap();
        let parsed = JsonRpcParser::parse_response(&response).unwrap();

        assert!(parsed.is_error());
        assert_eq!(parsed.id, RequestId::Null);
        assert_eq!(parsed.error.unwrap().code, -32600);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(!response.contains("plain-secret"));
        assert!(!response.contains("api_key"));

        let audit_dump = adapter
            .security_audit()
            .events()
            .iter()
            .map(|event| event.to_json())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(audit_dump.contains("invalid_request"));
        assert!(!audit_dump.contains("plain-secret"));
        assert!(!audit_dump.contains("api_key"));
    }

    #[test]
    fn jsonrpc_error_formatting_redacts_message_and_data() {
        let response = dcp::compat::JsonRpcResponse::error(
            RequestId::Number(1),
            JsonRpcError::with_data(
                -32000,
                "Bearer rpc-secret",
                serde_json::json!({
                    "authorization": "Bearer rpc-secret",
                    "safe": "ok"
                }),
            ),
        );

        let rendered = JsonRpcParser::format_response(&response).unwrap();

        assert!(!rendered.contains("rpc-secret"));
        assert!(rendered.contains("[REDACTED]"));
        assert!(rendered.contains("ok"));
    }

    #[tokio::test]
    async fn complete_adapter_denies_tools_without_registered_capability() {
        let adapter = CompleteMcpAdapter::new();
        let router = BinaryTrieRouter::new();

        let init = r#"{"jsonrpc":"2.0","method":"initialize","id":1}"#;
        adapter.handle_request(init, &router).await.unwrap();
        send_initialized(&adapter, &router).await;

        let response = adapter
            .handle_request(r#"{"jsonrpc":"2.0","method":"tools/list","id":2}"#, &router)
            .await
            .unwrap()
            .unwrap();
        let parsed = JsonRpcParser::parse_response(&response).unwrap();

        assert!(parsed.is_error());
        assert_eq!(parsed.error.unwrap().code, -32001);
    }

    #[tokio::test]
    async fn complete_adapter_intersects_empty_client_capabilities() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut adapter = CompleteMcpAdapter::new();
        adapter.register_tool("secret", 7).unwrap();

        let mut router = BinaryTrieRouter::new();
        router
            .register(Box::new(CountingTool {
                calls: Arc::clone(&calls),
            }))
            .unwrap();

        let init_response = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"initialize","params":{"capabilities":{}},"id":1}"#,
                &router,
            )
            .await
            .unwrap()
            .unwrap();
        let init = JsonRpcParser::parse_response(&init_response).unwrap();
        assert!(init.result.unwrap()["capabilities"]["tools"].is_null());
        send_initialized(&adapter, &router).await;

        let list_response = adapter
            .handle_request(r#"{"jsonrpc":"2.0","method":"tools/list","id":2}"#, &router)
            .await
            .unwrap()
            .unwrap();
        let list = JsonRpcParser::parse_response(&list_response).unwrap();
        assert_eq!(list.error.unwrap().code, -32001);

        let call_response = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"secret"},"id":3}"#,
                &router,
            )
            .await
            .unwrap()
            .unwrap();
        let call = JsonRpcParser::parse_response(&call_response).unwrap();
        assert_eq!(call.error.unwrap().code, -32001);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn complete_adapter_reinitialize_cannot_expand_negotiated_manifest() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut adapter = CompleteMcpAdapter::new();
        adapter.register_tool("secret", 7).unwrap();

        let mut router = BinaryTrieRouter::new();
        router
            .register(Box::new(CountingTool {
                calls: Arc::clone(&calls),
            }))
            .unwrap();

        adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"initialize","params":{"capabilities":{}},"id":1}"#,
                &router,
            )
            .await
            .unwrap();
        adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
                &router,
            )
            .await
            .unwrap();

        let reinit_response = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"initialize","params":{"capabilities":{"dcp":{"tools":[7]}}},"id":2}"#,
                &router,
            )
            .await
            .unwrap()
            .unwrap();
        let reinit = JsonRpcParser::parse_response(&reinit_response).unwrap();
        assert!(reinit.is_error());
        assert_eq!(reinit.error.unwrap().code, -32600);

        let call_response = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"secret"},"id":3}"#,
                &router,
            )
            .await
            .unwrap()
            .unwrap();
        let call = JsonRpcParser::parse_response(&call_response).unwrap();
        assert!(call.is_error());
        assert_eq!(call.error.unwrap().code, -32001);
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        assert!(adapter
            .security_audit()
            .events()
            .iter()
            .any(|event| event.reason == "invalid_request"
                && event.method.as_deref() == Some("initialize")));
    }

    #[tokio::test]
    async fn complete_adapter_rejects_out_of_range_dcp_capability_ids() {
        let adapter = CompleteMcpAdapter::new();
        let router = BinaryTrieRouter::new();

        let response = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"initialize","params":{"capabilities":{"dcp":{"tools":[8192],"resources":[1024],"prompts":[512],"extensions":[64]}}},"id":1}"#,
                &router,
            )
            .await
            .unwrap()
            .unwrap();
        let parsed = JsonRpcParser::parse_response(&response).unwrap();

        assert!(parsed.is_error());
        assert_eq!(parsed.error.unwrap().code, -32602);

        let valid_response = adapter
            .handle_request(r#"{"jsonrpc":"2.0","method":"initialize","id":2}"#, &router)
            .await
            .unwrap()
            .unwrap();
        let valid = JsonRpcParser::parse_response(&valid_response).unwrap();

        assert!(!valid.is_error());
    }

    #[tokio::test]
    async fn complete_adapter_rejects_non_object_initialize_params_without_consuming_initialize() {
        let adapter = CompleteMcpAdapter::new();
        let router = BinaryTrieRouter::new();

        let bad = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"initialize","params":[],"id":1}"#,
                &router,
            )
            .await
            .unwrap()
            .unwrap();
        let bad = JsonRpcParser::parse_response(&bad).unwrap();

        assert_eq!(bad.error.unwrap().code, -32602);

        let good = adapter
            .handle_request(r#"{"jsonrpc":"2.0","method":"initialize","id":2}"#, &router)
            .await
            .unwrap()
            .unwrap();
        let good = JsonRpcParser::parse_response(&good).unwrap();

        assert!(!good.is_error());
    }

    #[tokio::test]
    async fn complete_adapter_rejects_non_object_dcp_capabilities_without_consuming_initialize() {
        let adapter = CompleteMcpAdapter::new();
        let router = BinaryTrieRouter::new();

        let bad = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"initialize","params":{"capabilities":{"dcp":true}},"id":1}"#,
                &router,
            )
            .await
            .unwrap()
            .unwrap();
        let bad = JsonRpcParser::parse_response(&bad).unwrap();

        assert_eq!(bad.error.unwrap().code, -32602);

        let good = adapter
            .handle_request(r#"{"jsonrpc":"2.0","method":"initialize","id":2}"#, &router)
            .await
            .unwrap()
            .unwrap();
        let good = JsonRpcParser::parse_response(&good).unwrap();

        assert!(!good.is_error());
    }

    #[tokio::test]
    async fn complete_adapter_conflicting_dcp_capability_sources_do_not_escalate() {
        let mut adapter = CompleteMcpAdapter::new();
        adapter.register_tool("secret", 7).unwrap();
        let router = BinaryTrieRouter::new();

        let bad = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"initialize","params":{"dcpCapabilities":{"tools":[7]},"capabilities":{"dcp":{"tools":[]}}},"id":1}"#,
                &router,
            )
            .await
            .unwrap()
            .unwrap();
        let bad = JsonRpcParser::parse_response(&bad).unwrap();

        assert!(bad.is_error());
        assert_eq!(bad.error.unwrap().code, -32602);

        let good = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"initialize","params":{"capabilities":{"dcp":{"tools":[]}}},"id":2}"#,
                &router,
            )
            .await
            .unwrap()
            .unwrap();
        let good = JsonRpcParser::parse_response(&good).unwrap();

        assert!(!good.is_error());
        assert!(good.result.unwrap()["capabilities"]["tools"].is_null());
    }

    #[tokio::test]
    async fn complete_adapter_does_not_execute_tools_call_notification() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut adapter = CompleteMcpAdapter::new();
        adapter.register_tool("secret", 7).unwrap();

        let mut router = BinaryTrieRouter::new();
        router
            .register(Box::new(CountingTool {
                calls: Arc::clone(&calls),
            }))
            .unwrap();

        adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"initialize","params":{"capabilities":{"dcp":{"tools":[7]}}},"id":1}"#,
                &router,
            )
            .await
            .unwrap();
        send_initialized(&adapter, &router).await;

        let response = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"secret"}}"#,
                &router,
            )
            .await
            .unwrap();

        assert!(response.is_none());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(adapter
            .security_audit()
            .events()
            .iter()
            .any(|event| event.reason == "notification_not_allowed"));
    }

    #[tokio::test]
    async fn complete_adapter_filters_tools_list_to_negotiated_ids() {
        let mut adapter = CompleteMcpAdapter::new();
        adapter.register_tool("allowed", 7).unwrap();
        adapter.register_tool("hidden", 8).unwrap();
        let router = BinaryTrieRouter::new();

        adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"initialize","params":{"capabilities":{"dcp":{"tools":[7]}}},"id":1}"#,
                &router,
            )
            .await
            .unwrap();
        send_initialized(&adapter, &router).await;

        let response = adapter
            .handle_request(r#"{"jsonrpc":"2.0","method":"tools/list","id":2}"#, &router)
            .await
            .unwrap()
            .unwrap();
        let parsed = JsonRpcParser::parse_response(&response).unwrap();
        let tools = parsed.result.unwrap()["tools"].as_array().unwrap().clone();

        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["name"], "allowed");
    }

    #[test]
    fn complete_adapter_rejects_tool_registration_outside_manifest_capacity() {
        let mut adapter = CompleteMcpAdapter::new();

        let err = adapter
            .register_tool("overflow", CapabilityManifest::MAX_TOOLS as u16)
            .unwrap_err();

        assert!(matches!(
            err,
            CompleteAdapterError::CapacityExceeded { kind: "tool", .. }
        ));
    }

    #[test]
    fn complete_adapter_rejects_duplicate_tool_names_and_ids() {
        let mut adapter = CompleteMcpAdapter::new();

        let tool_id = adapter.register_tool("visible", 7).unwrap();
        let duplicate_name = adapter.register_tool("visible", 8).unwrap_err();
        let duplicate_id = adapter.register_tool("hidden", 7).unwrap_err();

        assert_eq!(tool_id, 7);
        assert!(matches!(
            duplicate_name,
            CompleteAdapterError::InvalidRequest(_)
        ));
        assert!(matches!(
            duplicate_id,
            CompleteAdapterError::InvalidRequest(_)
        ));
    }

    #[test]
    fn complete_adapter_audits_rejected_tool_registration_without_leaking_secret_name() {
        let mut adapter = CompleteMcpAdapter::new();

        let err = adapter
            .register_tool(
                "authorization=Bearer plain-secret",
                CapabilityManifest::MAX_TOOLS as u16,
            )
            .unwrap_err();

        assert!(matches!(
            err,
            CompleteAdapterError::CapacityExceeded { kind: "tool", .. }
        ));
        let events = adapter.security_audit().events();
        let event = events
            .iter()
            .find(|event| event.reason == "tool_registration_capacity_exceeded")
            .expect("registration failure audit receipt");

        assert_eq!(event.action, SecurityAuditAction::ValidationRejected);
        assert_eq!(
            event.fields.get("adapter").map(String::as_str),
            Some("complete_mcp")
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

    #[tokio::test]
    async fn complete_adapter_tools_list_publishes_handler_schema() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut adapter = CompleteMcpAdapter::new();
        adapter.register_tool("typed", 7).unwrap();

        let mut router = BinaryTrieRouter::new();
        router
            .register(Box::new(RequiredBoolTool::new(Arc::clone(&calls))))
            .unwrap();

        adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"initialize","params":{"capabilities":{"dcp":{"tools":[7]}}},"id":1}"#,
                &router,
            )
            .await
            .unwrap();
        send_initialized(&adapter, &router).await;

        let response = adapter
            .handle_request(r#"{"jsonrpc":"2.0","method":"tools/list","id":2}"#, &router)
            .await
            .unwrap()
            .unwrap();
        let parsed = JsonRpcParser::parse_response(&response).unwrap();
        let tool = &parsed.result.unwrap()["tools"][0];

        assert_eq!(
            tool["inputSchema"]["properties"]["enabled"]["type"],
            "boolean"
        );
        assert_eq!(tool["inputSchema"]["required"][0], "enabled");
        assert_eq!(tool["inputSchema"]["additionalProperties"], false);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn complete_adapter_tools_call_translates_json_arguments_through_schema() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut adapter = CompleteMcpAdapter::new();
        adapter.register_tool("typed", 7).unwrap();

        let mut router = BinaryTrieRouter::new();
        router
            .register(Box::new(RequiredBoolTool::new(Arc::clone(&calls))))
            .unwrap();

        adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"initialize","params":{"capabilities":{"dcp":{"tools":[7]}}},"id":1}"#,
                &router,
            )
            .await
            .unwrap();
        send_initialized(&adapter, &router).await;

        let response = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"typed","arguments":{"enabled":true}},"id":2}"#,
                &router,
            )
            .await
            .unwrap()
            .unwrap();
        let parsed = JsonRpcParser::parse_response(&response).unwrap();

        assert!(parsed.is_success());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(response.contains("accepted"));
    }

    #[tokio::test]
    async fn complete_adapter_tools_call_rejects_wrong_json_argument_type() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut adapter = CompleteMcpAdapter::new();
        adapter.register_tool("typed", 7).unwrap();

        let mut router = BinaryTrieRouter::new();
        router
            .register(Box::new(RequiredBoolTool::new(Arc::clone(&calls))))
            .unwrap();

        adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"initialize","params":{"capabilities":{"dcp":{"tools":[7]}}},"id":1}"#,
                &router,
            )
            .await
            .unwrap();
        send_initialized(&adapter, &router).await;

        let response = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"typed","arguments":{"enabled":"yes"}},"id":2}"#,
                &router,
            )
            .await
            .unwrap()
            .unwrap();
        let parsed = JsonRpcParser::parse_response(&response).unwrap();

        assert!(parsed.is_error());
        assert_eq!(parsed.error.unwrap().code, -32602);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn complete_adapter_tools_call_rejects_arguments_not_declared_by_schema() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut adapter = CompleteMcpAdapter::new();
        adapter.register_tool("secret", 7).unwrap();

        let mut router = BinaryTrieRouter::new();
        router
            .register(Box::new(CountingTool {
                calls: Arc::clone(&calls),
            }))
            .unwrap();

        adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"initialize","params":{"capabilities":{"dcp":{"tools":[7]}}},"id":1}"#,
                &router,
            )
            .await
            .unwrap();
        send_initialized(&adapter, &router).await;

        let response = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"secret","arguments":{"unexpected":true}},"id":2}"#,
                &router,
            )
            .await
            .unwrap()
            .unwrap();
        let parsed = JsonRpcParser::parse_response(&response).unwrap();

        assert!(parsed.is_error());
        assert_eq!(parsed.error.unwrap().code, -32602);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn complete_adapter_tools_call_rejects_unsupported_top_level_params_before_dispatch() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut adapter = CompleteMcpAdapter::new();
        adapter.register_tool("secret", 7).unwrap();

        let mut router = BinaryTrieRouter::new();
        router
            .register(Box::new(CountingTool {
                calls: Arc::clone(&calls),
            }))
            .unwrap();

        adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"initialize","params":{"capabilities":{"dcp":{"tools":[7]}}},"id":1}"#,
                &router,
            )
            .await
            .unwrap();
        send_initialized(&adapter, &router).await;

        let response = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"secret","arguments":{},"api_key":"plain-secret"},"id":2}"#,
                &router,
            )
            .await
            .unwrap()
            .unwrap();
        let parsed = JsonRpcParser::parse_response(&response).unwrap();

        assert!(parsed.is_error());
        assert_eq!(parsed.error.unwrap().code, -32602);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(!response.contains("plain-secret"));
        assert!(!response.contains("api_key"));

        let audit_dump = format!("{:?}", adapter.security_audit().events());
        assert!(!audit_dump.contains("plain-secret"));
        assert!(!audit_dump.contains("api_key"));
        assert!(adapter.security_audit().events().iter().any(|event| {
            event.action == SecurityAuditAction::ValidationRejected
                && event.reason == "invalid_params"
                && event.method.as_deref() == Some("tools/call")
        }));
    }

    #[tokio::test]
    async fn complete_adapter_tools_call_rejects_non_object_meta_before_dispatch() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut adapter = CompleteMcpAdapter::new();
        adapter.register_tool("secret", 7).unwrap();

        let mut router = BinaryTrieRouter::new();
        router
            .register(Box::new(CountingTool {
                calls: Arc::clone(&calls),
            }))
            .unwrap();

        adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"initialize","params":{"capabilities":{"dcp":{"tools":[7]}}},"id":1}"#,
                &router,
            )
            .await
            .unwrap();
        send_initialized(&adapter, &router).await;

        let response = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"secret","arguments":{},"_meta":"api_key=plain-secret"},"id":2}"#,
                &router,
            )
            .await
            .unwrap()
            .unwrap();
        let parsed = JsonRpcParser::parse_response(&response).unwrap();

        assert!(parsed.is_error());
        assert_eq!(parsed.error.unwrap().code, -32602);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(!response.contains("plain-secret"));
        assert!(!response.contains("api_key"));

        let audit_dump = format!("{:?}", adapter.security_audit().events());
        assert!(!audit_dump.contains("plain-secret"));
        assert!(!audit_dump.contains("api_key"));
        assert!(adapter.security_audit().events().iter().any(|event| {
            event.action == SecurityAuditAction::ValidationRejected
                && event.reason == "invalid_params"
                && event.method.as_deref() == Some("tools/call")
        }));
    }

    #[tokio::test]
    async fn complete_adapter_tools_call_rejects_replayed_request_id_without_dispatch() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut adapter = CompleteMcpAdapter::new();
        adapter.register_tool("secret", 7).unwrap();

        let mut router = BinaryTrieRouter::new();
        router
            .register(Box::new(CountingTool {
                calls: Arc::clone(&calls),
            }))
            .unwrap();

        adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"initialize","params":{"capabilities":{"dcp":{"tools":[7]}}},"id":1}"#,
                &router,
            )
            .await
            .unwrap();
        send_initialized(&adapter, &router).await;

        let request = r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"secret","arguments":{},"_meta":{"token":"api_key=plain-secret"}},"id":2}"#;
        let first = adapter
            .handle_request(request, &router)
            .await
            .unwrap()
            .unwrap();
        let first = JsonRpcParser::parse_response(&first).unwrap();
        assert!(first.is_success());
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let replay = adapter
            .handle_request(request, &router)
            .await
            .unwrap()
            .unwrap();
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

    #[tokio::test]
    async fn complete_adapter_tools_call_rejects_non_object_params_before_dispatch() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut adapter = CompleteMcpAdapter::new();
        adapter.register_tool("secret", 7).unwrap();

        let mut router = BinaryTrieRouter::new();
        router
            .register(Box::new(CountingTool {
                calls: Arc::clone(&calls),
            }))
            .unwrap();

        adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"initialize","params":{"capabilities":{"dcp":{"tools":[7]}}},"id":1}"#,
                &router,
            )
            .await
            .unwrap();
        send_initialized(&adapter, &router).await;

        let response = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"tools/call","params":["secret"],"id":2}"#,
                &router,
            )
            .await
            .unwrap()
            .unwrap();
        let parsed = JsonRpcParser::parse_response(&response).unwrap();

        assert!(parsed.is_error());
        assert_eq!(parsed.error.unwrap().code, -32602);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(adapter.security_audit().events().iter().any(|event| {
            event.action == SecurityAuditAction::ValidationRejected
                && event.reason == "invalid_params"
                && event.method.as_deref() == Some("tools/call")
        }));
    }

    #[tokio::test]
    async fn complete_adapter_direct_tools_call_enforces_negotiated_capability() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut adapter = CompleteMcpAdapter::new();
        adapter.register_tool("secret", 7).unwrap();

        let mut router = BinaryTrieRouter::new();
        router
            .register(Box::new(CountingTool {
                calls: Arc::clone(&calls),
            }))
            .unwrap();

        adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"initialize","params":{"capabilities":{}},"id":1}"#,
                &router,
            )
            .await
            .unwrap();
        send_initialized(&adapter, &router).await;
        let request = JsonRpcParser::parse_request(
            r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"secret"},"id":2}"#,
        )
        .unwrap();

        let err = adapter
            .handle_tools_call(&request, &router)
            .await
            .unwrap_err();

        assert!(matches!(err, CompleteAdapterError::CapabilityDenied));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn complete_adapter_direct_tools_list_denies_without_tool_capability() {
        let mut adapter = CompleteMcpAdapter::new();
        adapter.register_tool("secret", 7).unwrap();
        let router = BinaryTrieRouter::new();

        adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"initialize","params":{"capabilities":{}},"id":1}"#,
                &router,
            )
            .await
            .unwrap();
        send_initialized(&adapter, &router).await;
        let request =
            JsonRpcParser::parse_request(r#"{"jsonrpc":"2.0","method":"tools/list","id":2}"#)
                .unwrap();

        let err = adapter
            .handle_tools_list(&request, &router)
            .await
            .unwrap_err();

        assert!(matches!(err, CompleteAdapterError::CapabilityDenied));
    }

    #[tokio::test]
    async fn complete_adapter_list_methods_reject_malformed_params() {
        let mut adapter = CompleteMcpAdapter::new();
        adapter.register_tool("secret", 7).unwrap();
        adapter
            .register_prompt(
                PromptTemplate::new("allowed", "allowed prompt", "visible {{topic}}")
                    .with_argument("topic", "Topic", true),
            )
            .unwrap();

        let router = BinaryTrieRouter::new();
        let mut handler = MemoryResourceHandler::new("file:///allowed/{path}");
        handler.add_resource(
            "file:///allowed/readme.md",
            ResourceContent::text("file:///allowed/readme.md", "text/plain", "inside"),
        );
        adapter.resources().write().await.register(handler).unwrap();
        adapter.roots().add_root(Root::new("file:///allowed")).await;

        initialize_and_send_initialized(
            &adapter,
            &router,
            r#"{"jsonrpc":"2.0","method":"initialize","params":{"capabilities":{"dcp":{"tools":[7],"resources":[0],"prompts":[0]}}},"id":1}"#,
        )
        .await
        .unwrap();

        for request in [
            r#"{"jsonrpc":"2.0","method":"tools/list","params":[],"id":2}"#,
            r#"{"jsonrpc":"2.0","method":"tools/list","params":{"cursor":7},"id":3}"#,
            r#"{"jsonrpc":"2.0","method":"resources/list","params":[],"id":4}"#,
            r#"{"jsonrpc":"2.0","method":"resources/list","params":{"cursor":7},"id":5}"#,
            r#"{"jsonrpc":"2.0","method":"prompts/list","params":[],"id":6}"#,
            r#"{"jsonrpc":"2.0","method":"prompts/list","params":{"cursor":7},"id":7}"#,
        ] {
            let response = adapter
                .handle_request(request, &router)
                .await
                .unwrap()
                .unwrap();
            let parsed = JsonRpcParser::parse_response(&response).unwrap();

            assert!(parsed.is_error(), "{request}");
            assert_eq!(parsed.error.unwrap().code, -32602, "{request}");
        }
    }

    #[tokio::test]
    async fn complete_adapter_direct_handlers_reject_request_notification_mismatch() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut adapter = CompleteMcpAdapter::new();
        adapter.register_tool("secret", 7).unwrap();
        adapter
            .register_prompt(PromptTemplate::new("allowed", "allowed prompt", "visible"))
            .unwrap();

        let mut router = BinaryTrieRouter::new();
        router
            .register(Box::new(CountingTool {
                calls: Arc::clone(&calls),
            }))
            .unwrap();

        let mut handler = MemoryResourceHandler::new("file:///allowed/{path}");
        handler.add_resource(
            "file:///allowed/readme.md",
            ResourceContent::text("file:///allowed/readme.md", "text/plain", "inside"),
        );
        adapter.resources().write().await.register(handler).unwrap();
        adapter.roots().add_root(Root::new("file:///allowed")).await;

        initialize_and_send_initialized(
            &adapter,
            &router,
            r#"{"jsonrpc":"2.0","method":"initialize","params":{"capabilities":{"dcp":{"tools":[7],"resources":[0],"prompts":[0]}}},"id":1}"#,
        )
        .await
        .unwrap();

        let tool_call =
            JsonRpcRequest::notification("tools/call", Some(serde_json::json!({"name": "secret"})));
        assert!(matches!(
            adapter.handle_tools_call(&tool_call, &router).await,
            Err(CompleteAdapterError::InvalidRequest(_))
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        let tools_list = JsonRpcRequest::notification("tools/list", None);
        assert!(matches!(
            adapter.handle_tools_list(&tools_list, &router).await,
            Err(CompleteAdapterError::InvalidRequest(_))
        ));

        let resources_list = JsonRpcRequest::notification("resources/list", None);
        assert!(matches!(
            adapter.handle_resources_list(&resources_list).await,
            Err(CompleteAdapterError::InvalidRequest(_))
        ));

        let prompts_list = JsonRpcRequest::notification("prompts/list", None);
        assert!(matches!(
            adapter.handle_prompts_list(&prompts_list).await,
            Err(CompleteAdapterError::InvalidRequest(_))
        ));

        let cancelled_request = JsonRpcRequest::new(
            "notifications/cancelled",
            Some(serde_json::json!({"requestId": 7})),
            RequestId::Number(99),
        );
        assert!(matches!(
            adapter.handle_cancelled(&cancelled_request).await,
            Err(CompleteAdapterError::InvalidRequest(_))
        ));

        let read_as_ping = JsonRpcRequest::new(
            "ping",
            Some(serde_json::json!({"uri": "file:///allowed/readme.md"})),
            RequestId::Number(100),
        );
        assert!(matches!(
            adapter.handle_resources_read(&read_as_ping).await,
            Err(CompleteAdapterError::InvalidRequest(_))
        ));

        let unsubscribe_as_ping = JsonRpcRequest::new(
            "ping",
            Some(serde_json::json!({"uri": "file:///allowed/readme.md"})),
            RequestId::Number(101),
        );
        assert!(matches!(
            adapter
                .handle_resources_unsubscribe(&unsubscribe_as_ping)
                .await,
            Err(CompleteAdapterError::InvalidRequest(_))
        ));

        let prompt_as_ping = JsonRpcRequest::new(
            "ping",
            Some(serde_json::json!({"name": "allowed", "arguments": {"topic": "safe"}})),
            RequestId::Number(102),
        );
        assert!(matches!(
            adapter.handle_prompts_get(&prompt_as_ping).await,
            Err(CompleteAdapterError::InvalidRequest(_))
        ));

        let logging_as_ping = JsonRpcRequest::new(
            "ping",
            Some(serde_json::json!({"level": "info"})),
            RequestId::Number(103),
        );
        assert!(matches!(
            adapter.handle_logging_set_level(&logging_as_ping).await,
            Err(CompleteAdapterError::InvalidRequest(_))
        ));

        let completion_as_ping = JsonRpcRequest::new(
            "ping",
            Some(serde_json::json!({
                "ref": {"type": "ref/resource", "uri": "file:///allowed/readme.md"},
                "argument": {"name": "path", "value": "readme"}
            })),
            RequestId::Number(104),
        );
        assert!(matches!(
            adapter
                .handle_completion_complete(&completion_as_ping)
                .await,
            Err(CompleteAdapterError::InvalidRequest(_))
        ));

        let ping_as_tools_list = JsonRpcRequest::new("tools/list", None, RequestId::Number(105));
        assert!(matches!(
            adapter.handle_ping(&ping_as_tools_list),
            Err(CompleteAdapterError::InvalidRequest(_))
        ));

        let roots_as_ping = JsonRpcRequest::new("ping", None, RequestId::Number(106));
        assert!(matches!(
            adapter.handle_roots_list(&roots_as_ping).await,
            Err(CompleteAdapterError::InvalidRequest(_))
        ));

        let elicitation_as_ping = JsonRpcRequest::new("ping", None, RequestId::Number(107));
        assert!(matches!(
            adapter
                .handle_elicitation_create(&elicitation_as_ping)
                .await,
            Err(CompleteAdapterError::InvalidRequest(_))
        ));

        let sampling_as_ping = JsonRpcRequest::new("ping", None, RequestId::Number(108));
        assert!(matches!(
            adapter
                .handle_sampling_create_message(&sampling_as_ping)
                .await,
            Err(CompleteAdapterError::InvalidRequest(_))
        ));
    }

    #[tokio::test]
    async fn complete_adapter_direct_initialize_requires_initialize_method() {
        let adapter = CompleteMcpAdapter::new();

        let initialize_as_ping = JsonRpcRequest::new(
            "ping",
            Some(serde_json::json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {}
            })),
            RequestId::Number(1),
        );
        assert!(matches!(
            adapter.handle_initialize(&initialize_as_ping).await,
            Err(CompleteAdapterError::InvalidRequest(_))
        ));

        let initialize = JsonRpcRequest::new(
            "initialize",
            Some(serde_json::json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {}
            })),
            RequestId::Number(2),
        );
        assert!(adapter.handle_initialize(&initialize).await.is_ok());
    }

    #[tokio::test]
    async fn complete_adapter_rejects_unsupported_protocol_version_without_consuming_initialize() {
        let adapter = CompleteMcpAdapter::new();
        let router = BinaryTrieRouter::new();

        let rejected = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2099-12-31","capabilities":{}},"id":1}"#,
                &router,
            )
            .await
            .unwrap()
            .unwrap();
        let rejected = JsonRpcParser::parse_response(&rejected).unwrap();
        assert!(rejected.is_error());
        assert_eq!(rejected.error.unwrap().code, -32602);

        let accepted = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{}},"id":2}"#,
                &router,
            )
            .await
            .unwrap()
            .unwrap();
        let accepted = JsonRpcParser::parse_response(&accepted).unwrap();
        assert_eq!(
            accepted
                .result
                .as_ref()
                .and_then(|result| result.get("protocolVersion"))
                .and_then(|version| version.as_str()),
            Some("2025-06-18")
        );
    }

    #[tokio::test]
    async fn complete_adapter_authorization_policy_further_restricts_requested_capabilities() {
        let mut policy = CapabilityManifest::new(1);
        policy.set_tool(7);

        let mut adapter = CompleteMcpAdapter::new().with_authorization_policy(policy);
        adapter.register_tool("allowed", 7).unwrap();
        adapter.register_tool("registered-but-denied", 8).unwrap();

        let router = BinaryTrieRouter::new();
        let response = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"initialize","params":{"capabilities":{"dcp":{"tools":[7,8]}}},"id":1}"#,
                &router,
            )
            .await
            .unwrap()
            .unwrap();
        send_initialized(&adapter, &router).await;

        let parsed = JsonRpcParser::parse_response(&response).unwrap();
        let tools_capability = parsed
            .result
            .as_ref()
            .and_then(|result| result.get("capabilities"))
            .and_then(|capabilities| capabilities.get("tools"));
        assert!(tools_capability.is_some());

        let list_response = adapter
            .handle_request(r#"{"jsonrpc":"2.0","method":"tools/list","id":2}"#, &router)
            .await
            .unwrap()
            .unwrap();
        assert!(list_response.contains("allowed"));
        assert!(!list_response.contains("registered-but-denied"));

        let denied_response = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"registered-but-denied"},"id":3}"#,
                &router,
            )
            .await
            .unwrap()
            .unwrap();
        let denied = JsonRpcParser::parse_response(&denied_response).unwrap();
        assert_eq!(denied.error.unwrap().code, -32001);
    }

    #[test]
    fn legacy_mcp_adapter_tools_call_hides_unknown_vs_unnegotiated_tools() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut adapter = McpAdapter::new();
        adapter.register_tool("secret", 7).unwrap();

        let adapter = adapter.with_negotiated_capabilities(CapabilityManifest::new(1));
        let mut router = BinaryTrieRouter::new();
        router
            .register(Box::new(CountingTool {
                calls: Arc::clone(&calls),
            }))
            .unwrap();

        let hidden_request = JsonRpcParser::parse_request(
            r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"secret"},"id":2}"#,
        )
        .unwrap();
        let unknown_request = JsonRpcParser::parse_request(
            r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"access_token=plain-secret"},"id":3}"#,
        )
        .unwrap();

        let hidden_response = adapter.handle_tools_call(&hidden_request, &router).unwrap();
        let unknown_response = adapter
            .handle_tools_call(&unknown_request, &router)
            .unwrap();

        let hidden_error = JsonRpcParser::parse_response(&hidden_response)
            .unwrap()
            .error
            .unwrap();
        let unknown_error = JsonRpcParser::parse_response(&unknown_response)
            .unwrap()
            .error
            .unwrap();

        assert_eq!(hidden_error.code, -32001);
        assert_eq!(unknown_error.code, hidden_error.code);
        assert_eq!(unknown_error.message, hidden_error.message);
        assert!(!unknown_response.contains("plain-secret"));
        let audit_dump = format!("{:?}", adapter.security_audit().events());
        assert!(!audit_dump.contains("plain-secret"));
        assert!(!audit_dump.contains("access_token"));
        assert!(adapter.security_audit().events().iter().any(|event| {
            event.reason == "capability_denied"
                && event.method.as_deref() == Some("tools/call")
                && event.action == SecurityAuditAction::CapabilityDenied
        }));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn legacy_mcp_adapter_tools_list_denies_without_negotiated_manifest() {
        let mut adapter = McpAdapter::new();
        adapter.register_tool("secret", 7).unwrap();
        let request =
            JsonRpcParser::parse_request(r#"{"jsonrpc":"2.0","method":"tools/list","id":1}"#)
                .unwrap();

        let response = adapter.handle_tools_list(&request).unwrap();
        let parsed = JsonRpcParser::parse_response(&response).unwrap();

        assert!(parsed.is_error());
        assert_eq!(parsed.error.unwrap().code, -32001);
        assert!(!response.contains("secret"));
        assert!(adapter.security_audit().events().iter().any(|event| {
            event.reason == "capability_denied"
                && event.method.as_deref() == Some("tools/list")
                && event.action == SecurityAuditAction::CapabilityDenied
        }));
    }

    #[test]
    fn legacy_mcp_adapter_tools_list_denies_empty_negotiated_manifest() {
        let mut adapter = McpAdapter::new();
        adapter.register_tool("secret", 7).unwrap();
        let adapter = adapter.with_negotiated_capabilities(CapabilityManifest::new(1));
        let request =
            JsonRpcParser::parse_request(r#"{"jsonrpc":"2.0","method":"tools/list","id":1}"#)
                .unwrap();

        let response = adapter.handle_tools_list(&request).unwrap();
        let parsed = JsonRpcParser::parse_response(&response).unwrap();

        assert!(parsed.is_error());
        assert_eq!(parsed.error.unwrap().code, -32001);
        assert!(!response.contains("secret"));
    }

    #[tokio::test]
    async fn complete_adapter_tools_call_hides_unknown_vs_unnegotiated_tools() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut adapter = CompleteMcpAdapter::new();
        adapter.register_tool("secret", 7).unwrap();

        let mut router = BinaryTrieRouter::new();
        router
            .register(Box::new(CountingTool {
                calls: Arc::clone(&calls),
            }))
            .unwrap();

        adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"initialize","params":{"capabilities":{}},"id":1}"#,
                &router,
            )
            .await
            .unwrap();
        send_initialized(&adapter, &router).await;

        let hidden_response = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"secret"},"id":2}"#,
                &router,
            )
            .await
            .unwrap()
            .unwrap();
        let unknown_response = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"missing"},"id":3}"#,
                &router,
            )
            .await
            .unwrap()
            .unwrap();

        let hidden_error = JsonRpcParser::parse_response(&hidden_response)
            .unwrap()
            .error
            .unwrap();
        let unknown_error = JsonRpcParser::parse_response(&unknown_response)
            .unwrap()
            .error
            .unwrap();

        assert_eq!(hidden_error.code, -32001);
        assert_eq!(unknown_error.code, hidden_error.code);
        assert_eq!(unknown_error.message, hidden_error.message);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn complete_adapter_tools_call_capability_denied_has_one_audit_receipt() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut adapter = CompleteMcpAdapter::new();
        adapter.register_tool("secret", 7).unwrap();

        let mut router = BinaryTrieRouter::new();
        router
            .register(Box::new(CountingTool {
                calls: Arc::clone(&calls),
            }))
            .unwrap();

        adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"initialize","params":{"capabilities":{}},"id":1}"#,
                &router,
            )
            .await
            .unwrap();
        send_initialized(&adapter, &router).await;

        adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"secret"},"id":2}"#,
                &router,
            )
            .await
            .unwrap()
            .unwrap();

        let denial_receipts = adapter
            .security_audit()
            .events()
            .iter()
            .filter(|event| {
                event.reason == "capability_denied" && event.method.as_deref() == Some("tools/call")
            })
            .count();

        assert_eq!(denial_receipts, 1);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn complete_adapter_filters_resources_list_to_negotiated_ids() {
        let adapter = CompleteMcpAdapter::new();
        let router = BinaryTrieRouter::new();

        let mut allowed = MemoryResourceHandler::new("file:///allowed/{path}");
        allowed.add_resource(
            "file:///allowed/readme.md",
            ResourceContent::text("file:///allowed/readme.md", "text/plain", "inside"),
        );
        let mut hidden = MemoryResourceHandler::new("file:///hidden/{path}");
        hidden.add_resource(
            "file:///hidden/secret.md",
            ResourceContent::text("file:///hidden/secret.md", "text/plain", "secret"),
        );
        adapter.resources().write().await.register(allowed).unwrap();
        adapter.resources().write().await.register(hidden).unwrap();
        adapter.roots().add_root(Root::new("file:///allowed")).await;

        adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"initialize","params":{"capabilities":{"dcp":{"resources":[0]}}},"id":1}"#,
                &router,
            )
            .await
            .unwrap();
        send_initialized(&adapter, &router).await;

        let response = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"resources/list","id":2}"#,
                &router,
            )
            .await
            .unwrap()
            .unwrap();
        let parsed = JsonRpcParser::parse_response(&response).unwrap();
        let resources = parsed.result.unwrap()["resources"]
            .as_array()
            .unwrap()
            .clone();

        assert_eq!(resources.len(), 1);
        assert_eq!(resources[0]["uri"], "file:///allowed/readme.md");
        assert!(!response.contains("hidden"));
        assert!(!response.contains("secret"));
    }

    #[tokio::test]
    async fn complete_adapter_direct_resources_list_denies_without_resource_capability() {
        let adapter = CompleteMcpAdapter::new();
        let router = BinaryTrieRouter::new();

        let mut handler = MemoryResourceHandler::new("file:///secret/{path}");
        handler.add_resource(
            "file:///secret/readme.md",
            ResourceContent::text("file:///secret/readme.md", "text/plain", "secret"),
        );
        adapter.resources().write().await.register(handler).unwrap();
        adapter.roots().add_root(Root::new("file:///secret")).await;

        adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"initialize","params":{"capabilities":{}},"id":1}"#,
                &router,
            )
            .await
            .unwrap();
        send_initialized(&adapter, &router).await;
        let request =
            JsonRpcParser::parse_request(r#"{"jsonrpc":"2.0","method":"resources/list","id":2}"#)
                .unwrap();

        let err = adapter.handle_resources_list(&request).await.unwrap_err();

        assert!(matches!(err, CompleteAdapterError::CapabilityDenied));
    }

    #[tokio::test]
    async fn complete_adapter_filters_resources_list_to_configured_roots() {
        let adapter = CompleteMcpAdapter::new();
        let router = BinaryTrieRouter::new();

        let mut handler = MemoryResourceHandler::new("file:///{path}");
        handler.add_resource(
            "file:///allowed/readme.md",
            ResourceContent::text("file:///allowed/readme.md", "text/plain", "inside"),
        );
        handler.add_resource(
            "file:///secret.txt",
            ResourceContent::text("file:///secret.txt", "text/plain", "outside-secret"),
        );
        adapter.resources().write().await.register(handler).unwrap();
        adapter.roots().add_root(Root::new("file:///allowed")).await;

        adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{"dcp":{"resources":[0]}}},"id":1}"#,
                &router,
            )
            .await
            .unwrap();
        send_initialized(&adapter, &router).await;

        let response = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"resources/list","id":2}"#,
                &router,
            )
            .await
            .unwrap()
            .unwrap();
        let parsed = JsonRpcParser::parse_response(&response).unwrap();
        let resources = parsed.result.unwrap()["resources"]
            .as_array()
            .unwrap()
            .clone();

        assert_eq!(resources.len(), 1);
        assert_eq!(resources[0]["uri"], "file:///allowed/readme.md");
        assert!(!response.contains("secret.txt"));
        assert!(!response.contains("outside-secret"));
    }

    #[tokio::test]
    async fn complete_adapter_denies_resource_read_for_unnegotiated_id() {
        let adapter = CompleteMcpAdapter::new();
        let router = BinaryTrieRouter::new();

        let mut allowed = MemoryResourceHandler::new("file:///allowed/{path}");
        allowed.add_resource(
            "file:///allowed/readme.md",
            ResourceContent::text("file:///allowed/readme.md", "text/plain", "inside"),
        );
        let mut hidden = MemoryResourceHandler::new("file:///hidden/{path}");
        hidden.add_resource(
            "file:///hidden/secret.md",
            ResourceContent::text("file:///hidden/secret.md", "text/plain", "hidden-secret"),
        );
        adapter.resources().write().await.register(allowed).unwrap();
        adapter.resources().write().await.register(hidden).unwrap();
        adapter.roots().add_root(Root::new("file:///")).await;

        adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"initialize","params":{"capabilities":{"dcp":{"resources":[0]}}},"id":1}"#,
                &router,
            )
            .await
            .unwrap();
        send_initialized(&adapter, &router).await;

        let response = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"resources/read","params":{"uri":"file:///hidden/secret.md"},"id":2}"#,
                &router,
            )
            .await
            .unwrap()
            .unwrap();
        let parsed = JsonRpcParser::parse_response(&response).unwrap();

        assert!(parsed.is_error());
        assert_eq!(parsed.error.unwrap().code, -32001);
        assert!(!response.contains("hidden-secret"));
    }

    #[tokio::test]
    async fn complete_adapter_resource_read_hides_unknown_vs_unnegotiated_resource() {
        let adapter = CompleteMcpAdapter::new();
        let router = BinaryTrieRouter::new();

        let mut allowed = MemoryResourceHandler::new("file:///allowed/{path}");
        allowed.add_resource(
            "file:///allowed/readme.md",
            ResourceContent::text("file:///allowed/readme.md", "text/plain", "inside"),
        );
        let mut hidden = MemoryResourceHandler::new("file:///hidden/{path}");
        hidden.add_resource(
            "file:///hidden/secret.md",
            ResourceContent::text("file:///hidden/secret.md", "text/plain", "hidden-secret"),
        );
        adapter.resources().write().await.register(allowed).unwrap();
        adapter.resources().write().await.register(hidden).unwrap();
        adapter.roots().add_root(Root::new("file:///")).await;

        adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"initialize","params":{"capabilities":{"dcp":{"resources":[0]}}},"id":1}"#,
                &router,
            )
            .await
            .unwrap();
        send_initialized(&adapter, &router).await;

        let hidden_response = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"resources/read","params":{"uri":"file:///hidden/secret.md"},"id":2}"#,
                &router,
            )
            .await
            .unwrap()
            .unwrap();
        let unknown_response = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"resources/read","params":{"uri":"file:///missing/secret.md"},"id":3}"#,
                &router,
            )
            .await
            .unwrap()
            .unwrap();

        let hidden_error = JsonRpcParser::parse_response(&hidden_response)
            .unwrap()
            .error
            .unwrap();
        let unknown_error = JsonRpcParser::parse_response(&unknown_response)
            .unwrap()
            .error
            .unwrap();

        assert_eq!(hidden_error.code, -32001);
        assert_eq!(unknown_error.code, hidden_error.code);
        assert_eq!(unknown_error.message, hidden_error.message);
        assert!(!hidden_response.contains("hidden-secret"));
        assert!(!unknown_response.contains("missing/secret"));
    }

    #[tokio::test]
    async fn complete_adapter_rejects_subscribe_for_missing_concrete_resource() {
        let adapter = CompleteMcpAdapter::new();
        let router = BinaryTrieRouter::new();

        let mut handler = MemoryResourceHandler::new("file:///allowed/{path}").with_subscriptions();
        handler.add_resource(
            "file:///allowed/readme.md",
            ResourceContent::text("file:///allowed/readme.md", "text/plain", "inside"),
        );
        adapter.resources().write().await.register(handler).unwrap();
        adapter.roots().add_root(Root::new("file:///allowed")).await;

        adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{"dcp":{"resources":[0]}}},"id":1}"#,
                &router,
            )
            .await
            .unwrap();
        send_initialized(&adapter, &router).await;

        let response = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"resources/subscribe","params":{"uri":"file:///allowed/missing-secret.md"},"id":2}"#,
                &router,
            )
            .await
            .unwrap()
            .unwrap();
        let parsed = JsonRpcParser::parse_response(&response).unwrap();

        assert!(parsed.is_error());
        assert_eq!(parsed.error.unwrap().code, -32602);
        assert!(!response.contains("missing-secret"));
    }

    #[tokio::test]
    async fn complete_adapter_rejects_subscribe_when_handler_does_not_support_it() {
        let adapter = CompleteMcpAdapter::new();
        let router = BinaryTrieRouter::new();

        let mut handler = MemoryResourceHandler::new("file:///allowed/{path}");
        handler.add_resource(
            "file:///allowed/readme.md",
            ResourceContent::text("file:///allowed/readme.md", "text/plain", "inside"),
        );
        adapter.resources().write().await.register(handler).unwrap();
        adapter.roots().add_root(Root::new("file:///allowed")).await;

        adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{"dcp":{"resources":[0]}}},"id":1}"#,
                &router,
            )
            .await
            .unwrap();
        send_initialized(&adapter, &router).await;

        let response = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"resources/subscribe","params":{"uri":"file:///allowed/readme.md"},"id":2}"#,
                &router,
            )
            .await
            .unwrap()
            .unwrap();
        let parsed = JsonRpcParser::parse_response(&response).unwrap();

        assert!(parsed.is_error());
        assert_eq!(parsed.error.unwrap().code, -32602);
        assert!(!response.contains("inside"));
    }

    #[tokio::test]
    async fn complete_adapter_filters_resource_templates_to_negotiated_ids() {
        let adapter = CompleteMcpAdapter::new();
        let router = BinaryTrieRouter::new();

        let mut allowed = MemoryResourceHandler::new("file:///allowed/{path}");
        allowed.add_resource(
            "file:///allowed/readme.md",
            ResourceContent::text("file:///allowed/readme.md", "text/plain", "inside"),
        );
        let mut hidden = MemoryResourceHandler::new("file:///hidden/{path}");
        hidden.add_resource(
            "file:///hidden/secret.md",
            ResourceContent::text("file:///hidden/secret.md", "text/plain", "hidden-secret"),
        );
        adapter.resources().write().await.register(allowed).unwrap();
        adapter.resources().write().await.register(hidden).unwrap();
        adapter
            .resource_templates()
            .register(ResourceTemplate::new(
                "file:///allowed/{path}",
                "Allowed files",
            ))
            .await;
        adapter
            .resource_templates()
            .register(ResourceTemplate::new(
                "file:///hidden/{path}",
                "Hidden files",
            ))
            .await;

        adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{"dcp":{"resources":[0]}}},"id":1}"#,
                &router,
            )
            .await
            .unwrap();
        send_initialized(&adapter, &router).await;

        let response = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"resources/list","id":2}"#,
                &router,
            )
            .await
            .unwrap()
            .unwrap();
        let parsed = JsonRpcParser::parse_response(&response).unwrap();
        let templates = parsed.result.unwrap()["resourceTemplates"]
            .as_array()
            .unwrap()
            .clone();

        assert_eq!(templates.len(), 1);
        assert_eq!(templates[0]["uriTemplate"], "file:///allowed/{path}");
        assert!(!response.contains("hidden"));
        assert!(!response.contains("Hidden files"));
    }

    #[tokio::test]
    async fn complete_adapter_filters_prompts_list_to_negotiated_ids() {
        let mut adapter = CompleteMcpAdapter::new();
        adapter
            .register_prompt(PromptTemplate::new("allowed", "allowed prompt", "visible"))
            .unwrap();
        adapter
            .register_prompt(PromptTemplate::new("hidden", "hidden prompt", "secret"))
            .unwrap();
        let router = BinaryTrieRouter::new();

        adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"initialize","params":{"capabilities":{"dcp":{"prompts":[0]}}},"id":1}"#,
                &router,
            )
            .await
            .unwrap();
        send_initialized(&adapter, &router).await;

        let response = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"prompts/list","id":2}"#,
                &router,
            )
            .await
            .unwrap()
            .unwrap();
        let parsed = JsonRpcParser::parse_response(&response).unwrap();
        let prompts = parsed.result.unwrap()["prompts"]
            .as_array()
            .unwrap()
            .clone();

        assert_eq!(prompts.len(), 1);
        assert_eq!(prompts[0]["name"], "allowed");
        assert!(!response.contains("hidden"));
        assert!(!response.contains("secret"));
    }

    #[test]
    fn complete_adapter_rejects_prompt_registration_beyond_manifest_capacity() {
        let mut adapter = CompleteMcpAdapter::new();

        for i in 0..CapabilityManifest::MAX_PROMPTS {
            let prompt_id = adapter
                .register_prompt(PromptTemplate::new(
                    format!("prompt-{i}"),
                    "prompt",
                    "template",
                ))
                .unwrap();
            assert_eq!(usize::from(prompt_id), i);
        }

        let err = adapter
            .register_prompt(PromptTemplate::new("overflow", "prompt", "secret"))
            .unwrap_err();

        assert!(matches!(
            err,
            CompleteAdapterError::CapacityExceeded { kind: "prompt", .. }
        ));
    }

    #[test]
    fn complete_adapter_rejects_duplicate_prompt_names() {
        let mut adapter = CompleteMcpAdapter::new();

        let prompt_id = adapter
            .register_prompt(PromptTemplate::new("duplicate", "prompt", "visible"))
            .unwrap();
        assert_eq!(prompt_id, 0);

        let err = adapter
            .register_prompt(PromptTemplate::new("duplicate", "replacement", "secret"))
            .unwrap_err();

        assert!(matches!(err, CompleteAdapterError::InvalidRequest(_)));
    }

    #[tokio::test]
    async fn complete_adapter_direct_prompts_list_denies_without_prompt_capability() {
        let mut adapter = CompleteMcpAdapter::new();
        adapter
            .register_prompt(PromptTemplate::new(
                "hidden",
                "hidden prompt",
                "hidden-secret",
            ))
            .unwrap();
        let router = BinaryTrieRouter::new();

        adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"initialize","params":{"capabilities":{}},"id":1}"#,
                &router,
            )
            .await
            .unwrap();
        send_initialized(&adapter, &router).await;
        let request =
            JsonRpcParser::parse_request(r#"{"jsonrpc":"2.0","method":"prompts/list","id":2}"#)
                .unwrap();

        let err = adapter.handle_prompts_list(&request).await.unwrap_err();

        assert!(matches!(err, CompleteAdapterError::CapabilityDenied));
    }

    #[tokio::test]
    async fn complete_adapter_denies_prompt_get_for_unnegotiated_id() {
        let mut adapter = CompleteMcpAdapter::new();
        adapter
            .register_prompt(PromptTemplate::new("allowed", "allowed prompt", "visible"))
            .unwrap();
        adapter
            .register_prompt(PromptTemplate::new(
                "hidden",
                "hidden prompt",
                "hidden-secret",
            ))
            .unwrap();
        let router = BinaryTrieRouter::new();

        adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"initialize","params":{"capabilities":{"dcp":{"prompts":[0]}}},"id":1}"#,
                &router,
            )
            .await
            .unwrap();
        send_initialized(&adapter, &router).await;

        let response = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"prompts/get","params":{"name":"hidden"},"id":2}"#,
                &router,
            )
            .await
            .unwrap()
            .unwrap();
        let parsed = JsonRpcParser::parse_response(&response).unwrap();

        assert!(parsed.is_error());
        assert_eq!(parsed.error.unwrap().code, -32001);
        assert!(!response.contains("hidden-secret"));
    }

    #[tokio::test]
    async fn complete_adapter_prompt_get_hides_unknown_vs_unnegotiated_prompt() {
        let mut adapter = CompleteMcpAdapter::new();
        adapter
            .register_prompt(PromptTemplate::new("allowed", "allowed prompt", "visible"))
            .unwrap();
        adapter
            .register_prompt(PromptTemplate::new(
                "hidden",
                "hidden prompt",
                "hidden-secret",
            ))
            .unwrap();
        let router = BinaryTrieRouter::new();

        adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"initialize","params":{"capabilities":{"dcp":{"prompts":[0]}}},"id":1}"#,
                &router,
            )
            .await
            .unwrap();
        send_initialized(&adapter, &router).await;

        let hidden_response = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"prompts/get","params":{"name":"hidden"},"id":2}"#,
                &router,
            )
            .await
            .unwrap()
            .unwrap();
        let unknown_response = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"prompts/get","params":{"name":"missing"},"id":3}"#,
                &router,
            )
            .await
            .unwrap()
            .unwrap();

        let hidden_error = JsonRpcParser::parse_response(&hidden_response)
            .unwrap()
            .error
            .unwrap();
        let unknown_error = JsonRpcParser::parse_response(&unknown_response)
            .unwrap()
            .error
            .unwrap();

        assert_eq!(hidden_error.code, -32001);
        assert_eq!(unknown_error.code, hidden_error.code);
        assert_eq!(unknown_error.message, hidden_error.message);
        assert!(!hidden_response.contains("hidden-secret"));
        assert!(!unknown_response.contains("missing"));
    }

    #[tokio::test]
    async fn complete_adapter_prompt_get_rejects_undeclared_arguments() {
        let mut adapter = CompleteMcpAdapter::new();
        adapter
            .register_prompt(
                PromptTemplate::new("allowed", "allowed prompt", "Hello {{name}}!")
                    .with_argument("name", "Name", true),
            )
            .unwrap();
        let router = BinaryTrieRouter::new();

        adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"initialize","params":{"capabilities":{"dcp":{"prompts":[0]}}},"id":1}"#,
                &router,
            )
            .await
            .unwrap();
        send_initialized(&adapter, &router).await;

        let response = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"prompts/get","params":{"name":"allowed","arguments":{"name":"Ada","access_token":"plain-secret"}},"id":2}"#,
                &router,
            )
            .await
            .unwrap()
            .unwrap();
        let parsed = JsonRpcParser::parse_response(&response).unwrap();

        assert!(parsed.is_error());
        assert_eq!(parsed.error.unwrap().code, -32602);
        assert!(!response.contains("plain-secret"));
    }

    #[tokio::test]
    async fn complete_adapter_prompt_get_rejects_non_string_argument_values() {
        let mut adapter = CompleteMcpAdapter::new();
        adapter
            .register_prompt(
                PromptTemplate::new("allowed", "allowed prompt", "Hello {{name}}!")
                    .with_argument("name", "Name", true),
            )
            .unwrap();
        let router = BinaryTrieRouter::new();

        adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"initialize","params":{"capabilities":{"dcp":{"prompts":[0]}}},"id":1}"#,
                &router,
            )
            .await
            .unwrap();
        send_initialized(&adapter, &router).await;

        let response = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"prompts/get","params":{"name":"allowed","arguments":{"name":{"api_key":"plain-secret"}}},"id":2}"#,
                &router,
            )
            .await
            .unwrap()
            .unwrap();
        let parsed = JsonRpcParser::parse_response(&response).unwrap();

        assert!(parsed.is_error());
        assert_eq!(parsed.error.unwrap().code, -32602);
        assert!(!response.contains("plain-secret"));
    }

    #[tokio::test]
    async fn notification_only_method_with_id_returns_invalid_request() {
        let adapter = CompleteMcpAdapter::new();
        let router = BinaryTrieRouter::new();

        let response = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"notifications/initialized","id":1}"#,
                &router,
            )
            .await
            .unwrap()
            .unwrap();
        let parsed = JsonRpcParser::parse_response(&response).unwrap();

        assert_eq!(parsed.error.unwrap().code, -32600);
    }

    #[tokio::test]
    async fn complete_adapter_rejects_malformed_completion_params() {
        let adapter = CompleteMcpAdapter::new();
        let router = BinaryTrieRouter::new();
        initialize_and_send_initialized(
            &adapter,
            &router,
            r#"{"jsonrpc":"2.0","method":"initialize","id":1}"#,
        )
        .await
        .unwrap();

        let requests = [
            r#"{"jsonrpc":"2.0","method":"completion/complete","id":1}"#,
            r#"{"jsonrpc":"2.0","method":"completion/complete","params":{"ref":"not-object","argument":{"name":"token","value":"secret-value"}},"id":2}"#,
            r#"{"jsonrpc":"2.0","method":"completion/complete","params":{"ref":{"type":"ref/prompt","name":"x"},"argument":{"name":42,"value":"secret-value"}},"id":3}"#,
            r#"{"jsonrpc":"2.0","method":"completion/complete","params":{"ref":{"type":"ref/resource","uri":"file:///x"},"argument":{"name":"x","value":{"api_key":"secret-value"}}},"id":4}"#,
        ];

        for request in requests {
            let response = adapter
                .handle_request(request, &router)
                .await
                .unwrap()
                .unwrap();
            let parsed = JsonRpcParser::parse_response(&response).unwrap();

            assert!(parsed.is_error(), "request should fail: {request}");
            assert_eq!(parsed.error.unwrap().code, -32602);
            assert!(!response.contains("secret-value"));
        }
    }

    #[tokio::test]
    async fn complete_adapter_completion_denies_unnegotiated_prompt_ref() {
        let mut adapter = CompleteMcpAdapter::new();
        adapter
            .register_prompt(PromptTemplate::new("hidden", "hidden prompt", "secret"))
            .unwrap();
        let router = BinaryTrieRouter::new();

        adapter
            .handle_request(r#"{"jsonrpc":"2.0","method":"initialize","id":1}"#, &router)
            .await
            .unwrap();
        send_initialized(&adapter, &router).await;

        let response = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"completion/complete","params":{"ref":{"type":"ref/prompt","name":"hidden"},"argument":{"name":"topic","value":"sec"}},"id":2}"#,
                &router,
            )
            .await
            .unwrap()
            .unwrap();
        let parsed = JsonRpcParser::parse_response(&response).unwrap();

        assert!(parsed.is_error());
        assert_eq!(parsed.error.unwrap().code, -32001);
        assert!(adapter
            .security_audit()
            .events()
            .iter()
            .any(|event| event.reason == "capability_denied"
                && event.method.as_deref() == Some("completion/complete")));
    }

    #[tokio::test]
    async fn complete_adapter_completion_hides_unknown_vs_unnegotiated_prompt_ref() {
        let mut adapter = CompleteMcpAdapter::new();
        adapter
            .register_prompt(PromptTemplate::new("hidden", "hidden prompt", "secret"))
            .unwrap();
        let router = BinaryTrieRouter::new();

        adapter
            .handle_request(r#"{"jsonrpc":"2.0","method":"initialize","id":1}"#, &router)
            .await
            .unwrap();
        send_initialized(&adapter, &router).await;

        let hidden_response = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"completion/complete","params":{"ref":{"type":"ref/prompt","name":"hidden"},"argument":{"name":"topic","value":"sec"}},"id":2}"#,
                &router,
            )
            .await
            .unwrap()
            .unwrap();
        let unknown_response = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"completion/complete","params":{"ref":{"type":"ref/prompt","name":"missing"},"argument":{"name":"topic","value":"sec"}},"id":3}"#,
                &router,
            )
            .await
            .unwrap()
            .unwrap();

        let hidden_error = JsonRpcParser::parse_response(&hidden_response)
            .unwrap()
            .error
            .unwrap();
        let unknown_error = JsonRpcParser::parse_response(&unknown_response)
            .unwrap()
            .error
            .unwrap();

        assert_eq!(hidden_error.code, -32001);
        assert_eq!(unknown_error.code, hidden_error.code);
        assert_eq!(unknown_error.message, hidden_error.message);
        assert!(!hidden_response.contains("secret"));
        assert!(!unknown_response.contains("missing"));
    }

    #[tokio::test]
    async fn complete_adapter_completion_rejects_undeclared_prompt_argument() {
        let mut adapter = CompleteMcpAdapter::new();
        adapter
            .register_prompt(
                PromptTemplate::new("allowed", "allowed prompt", "Hello {{name}}!")
                    .with_argument("name", "Name", true),
            )
            .unwrap();
        let router = BinaryTrieRouter::new();

        adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"initialize","params":{"capabilities":{"dcp":{"prompts":[0]}}},"id":1}"#,
                &router,
            )
            .await
            .unwrap();
        send_initialized(&adapter, &router).await;

        let response = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"completion/complete","params":{"ref":{"type":"ref/prompt","name":"allowed"},"argument":{"name":"access_token","value":"plain-secret"}},"id":2}"#,
                &router,
            )
            .await
            .unwrap()
            .unwrap();
        let parsed = JsonRpcParser::parse_response(&response).unwrap();

        assert!(parsed.is_error());
        assert_eq!(parsed.error.unwrap().code, -32602);
        assert!(!response.contains("plain-secret"));
    }

    #[tokio::test]
    async fn complete_adapter_completion_denies_resource_ref_outside_capability_or_roots() {
        let adapter = CompleteMcpAdapter::new();
        let router = BinaryTrieRouter::new();

        let mut handler = MemoryResourceHandler::new("file:///{path}");
        handler.add_resource(
            "file:///hidden/secret.md",
            ResourceContent::text("file:///hidden/secret.md", "text/plain", "hidden-secret"),
        );
        adapter.resources().write().await.register(handler).unwrap();
        adapter.roots().add_root(Root::new("file:///allowed")).await;

        adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{"dcp":{"resources":[0]}}},"id":1}"#,
                &router,
            )
            .await
            .unwrap();
        send_initialized(&adapter, &router).await;

        let response = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"completion/complete","params":{"ref":{"type":"ref/resource","uri":"file:///hidden/secret.md"},"argument":{"name":"topic","value":"sec"}},"id":2}"#,
                &router,
            )
            .await
            .unwrap()
            .unwrap();
        let parsed = JsonRpcParser::parse_response(&response).unwrap();

        assert!(parsed.is_error());
        assert_eq!(parsed.error.unwrap().code, -32602);
        assert!(!response.contains("hidden-secret"));
    }

    #[tokio::test]
    async fn complete_adapter_completion_hides_unknown_vs_unnegotiated_resource_ref() {
        let adapter = CompleteMcpAdapter::new();
        let router = BinaryTrieRouter::new();

        let mut handler = MemoryResourceHandler::new("file:///hidden/{path}");
        handler.add_resource(
            "file:///hidden/secret.md",
            ResourceContent::text("file:///hidden/secret.md", "text/plain", "hidden-secret"),
        );
        adapter.resources().write().await.register(handler).unwrap();
        adapter.roots().add_root(Root::new("file:///")).await;

        adapter
            .handle_request(r#"{"jsonrpc":"2.0","method":"initialize","id":1}"#, &router)
            .await
            .unwrap();
        send_initialized(&adapter, &router).await;

        let hidden_response = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"completion/complete","params":{"ref":{"type":"ref/resource","uri":"file:///hidden/secret.md"},"argument":{"name":"topic","value":"sec"}},"id":2}"#,
                &router,
            )
            .await
            .unwrap()
            .unwrap();
        let unknown_response = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"completion/complete","params":{"ref":{"type":"ref/resource","uri":"file:///missing/secret.md"},"argument":{"name":"topic","value":"sec"}},"id":3}"#,
                &router,
            )
            .await
            .unwrap()
            .unwrap();

        let hidden_error = JsonRpcParser::parse_response(&hidden_response)
            .unwrap()
            .error
            .unwrap();
        let unknown_error = JsonRpcParser::parse_response(&unknown_response)
            .unwrap()
            .error
            .unwrap();

        assert_eq!(hidden_error.code, -32001);
        assert_eq!(unknown_error.code, hidden_error.code);
        assert_eq!(unknown_error.message, hidden_error.message);
        assert!(!hidden_response.contains("hidden-secret"));
        assert!(!unknown_response.contains("missing/secret"));
    }

    #[tokio::test]
    async fn complete_adapter_sanitizes_invalid_param_errors() {
        let adapter = CompleteMcpAdapter::new();
        let router = BinaryTrieRouter::new();

        adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"initialize","id":"init"}"#,
                &router,
            )
            .await
            .unwrap();
        send_initialized(&adapter, &router).await;

        let response = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"logging/setLevel","params":{"level":"password-super-secret"},"id":"req"}"#,
                &router,
            )
            .await
            .unwrap()
            .unwrap();

        assert!(!response.contains("password-super-secret"));

        let parsed = JsonRpcParser::parse_response(&response).unwrap();
        assert!(parsed.is_error());
        assert_eq!(parsed.error.unwrap().code, -32602);
    }

    #[tokio::test]
    async fn complete_adapter_records_security_audit_for_denied_request() {
        let adapter = CompleteMcpAdapter::new();
        let router = BinaryTrieRouter::new();

        adapter
            .handle_request(r#"{"jsonrpc":"2.0","method":"initialize","id":1}"#, &router)
            .await
            .unwrap();
        send_initialized(&adapter, &router).await;
        adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"tools/list","id":"req-2"}"#,
                &router,
            )
            .await
            .unwrap();

        let events = adapter.security_audit().events();

        assert!(events
            .iter()
            .any(|event| event.reason == "capability_denied"
                && event.method.as_deref() == Some("tools/list")));
    }

    #[tokio::test]
    async fn complete_adapter_audits_malformed_cancelled_notification() {
        let adapter = CompleteMcpAdapter::new();
        let router = BinaryTrieRouter::new();

        let response = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":{}}}"#,
                &router,
            )
            .await
            .unwrap();

        assert!(response.is_none());
        assert!(adapter
            .security_audit()
            .events()
            .iter()
            .any(|event| event.reason == "invalid_params"
                && event.method.as_deref() == Some("notifications/cancelled")));
    }

    #[tokio::test]
    async fn complete_adapter_rejects_secret_bearing_cancelled_request_id() {
        let adapter = CompleteMcpAdapter::new();
        let router = BinaryTrieRouter::new();

        let response = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"access_token=plain-secret","reason":"cancel"}}"#,
                &router,
            )
            .await
            .unwrap();

        assert!(response.is_none());
        assert!(adapter
            .security_audit()
            .events()
            .iter()
            .any(|event| event.reason == "request_id_sensitive"
                && event.method.as_deref() == Some("notifications/cancelled")));
        let audit_dump = format!("{:?}", adapter.security_audit().events());
        assert!(!audit_dump.contains("plain-secret"));
        assert!(!audit_dump.contains("access_token"));
    }

    #[tokio::test]
    async fn complete_adapter_rejects_oversized_cancelled_request_id() {
        let adapter = CompleteMcpAdapter::new();
        let router = BinaryTrieRouter::new();
        let oversized_id = "a".repeat(257);
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "notifications/cancelled",
            "params": {
                "requestId": oversized_id
            }
        })
        .to_string();

        let response = adapter.handle_request(&request, &router).await.unwrap();

        assert!(response.is_none());
        assert!(adapter
            .security_audit()
            .events()
            .iter()
            .any(|event| event.reason == "request_id_too_large"
                && event.method.as_deref() == Some("notifications/cancelled")));
    }

    #[tokio::test]
    async fn complete_adapter_sanitizes_cancelled_reason_before_storage() {
        let adapter = CompleteMcpAdapter::new();
        let router = BinaryTrieRouter::new();
        let request_id = RequestId::Number(7);
        let token = adapter
            .cancellation()
            .create_token(request_id.clone())
            .await;

        let response = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":7,"reason":"access_token=plain-secret"}}"#,
                &router,
            )
            .await
            .unwrap();

        assert!(response.is_none());
        assert!(token.is_cancelled());
        let reason = token.reason().await.unwrap();
        assert!(!reason.contains("plain-secret"));
        assert!(!reason.contains("access_token"));
        assert!(reason.contains("[REDACTED]"));
    }

    #[tokio::test]
    async fn complete_adapter_rejects_non_string_cancelled_reason_without_cancelling() {
        let adapter = CompleteMcpAdapter::new();
        let router = BinaryTrieRouter::new();
        let request_id = RequestId::Number(7);
        let token = adapter
            .cancellation()
            .create_token(request_id.clone())
            .await;

        let response = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":7,"reason":{"api_key":"plain-secret"}}}"#,
                &router,
            )
            .await
            .unwrap();

        assert!(response.is_none());
        assert!(!token.is_cancelled());
        assert!(adapter.security_audit().events().iter().any(|event| {
            event.reason == "invalid_params"
                && event.method.as_deref() == Some("notifications/cancelled")
        }));
        let audit_dump = format!("{:?}", adapter.security_audit().events());
        assert!(!audit_dump.contains("plain-secret"));
        assert!(!audit_dump.contains("api_key"));
    }

    #[tokio::test]
    async fn complete_adapter_rejects_extra_cancelled_params_without_cancelling_or_secret_leak() {
        let adapter = CompleteMcpAdapter::new();
        let router = BinaryTrieRouter::new();
        let request_id = RequestId::Number(7);
        let token = adapter
            .cancellation()
            .create_token(request_id.clone())
            .await;

        let response = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":7,"reason":"ok","api_key":"plain-secret"}}"#,
                &router,
            )
            .await
            .unwrap();

        assert!(response.is_none());
        assert!(!token.is_cancelled());
        assert!(adapter.security_audit().events().iter().any(|event| {
            event.action == SecurityAuditAction::ValidationRejected
                && event.reason == "invalid_params"
                && event.method.as_deref() == Some("notifications/cancelled")
        }));
        let audit_dump = format!("{:?}", adapter.security_audit().events());
        assert!(!audit_dump.contains("plain-secret"));
        assert!(!audit_dump.contains("api_key"));
    }

    #[tokio::test]
    async fn complete_adapter_denies_resource_read_outside_configured_root() {
        let adapter = CompleteMcpAdapter::new();
        let router = BinaryTrieRouter::new();

        let mut handler = MemoryResourceHandler::new("file:///{path}");
        handler.add_resource(
            "file:///allowed/readme.md",
            ResourceContent::text("file:///allowed/readme.md", "text/plain", "inside"),
        );
        handler.add_resource(
            "file:///secret.txt",
            ResourceContent::text("file:///secret.txt", "text/plain", "outside-secret"),
        );
        adapter.resources().write().await.register(handler).unwrap();
        adapter.roots().add_root(Root::new("file:///allowed")).await;

        adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{"dcp":{"resources":[0]}}},"id":1}"#,
                &router,
            )
            .await
            .unwrap();
        send_initialized(&adapter, &router).await;

        let response = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"resources/read","params":{"uri":"file:///secret.txt"},"id":2}"#,
                &router,
            )
            .await
            .unwrap()
            .unwrap();

        assert!(!response.contains("outside-secret"));
        let parsed = JsonRpcParser::parse_response(&response).unwrap();
        assert!(parsed.is_error());
        assert_eq!(parsed.error.unwrap().code, -32602);
    }

    #[tokio::test]
    async fn complete_adapter_denies_resource_unsubscribe_outside_configured_root() {
        let adapter = CompleteMcpAdapter::new();
        let router = BinaryTrieRouter::new();

        let mut handler = MemoryResourceHandler::new("file:///{path}");
        handler.add_resource(
            "file:///allowed/readme.md",
            ResourceContent::text("file:///allowed/readme.md", "text/plain", "inside"),
        );
        handler.add_resource(
            "file:///secret.txt",
            ResourceContent::text("file:///secret.txt", "text/plain", "outside-secret"),
        );
        adapter.resources().write().await.register(handler).unwrap();
        adapter.roots().add_root(Root::new("file:///allowed")).await;

        adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{"dcp":{"resources":[0]}}},"id":1}"#,
                &router,
            )
            .await
            .unwrap();
        send_initialized(&adapter, &router).await;

        let response = adapter
            .handle_request(
                r#"{"jsonrpc":"2.0","method":"resources/unsubscribe","params":{"uri":"file:///secret.txt"},"id":2}"#,
                &router,
            )
            .await
            .unwrap()
            .unwrap();

        assert!(!response.contains("outside-secret"));
        let parsed = JsonRpcParser::parse_response(&response).unwrap();
        assert!(parsed.is_error());
        assert_eq!(parsed.error.unwrap().code, -32602);
    }

    #[test]
    fn test_uri_template_basic() {
        assert!(uri_matches_template("file:///test.txt", "file:///{path}"));
        assert!(uri_matches_template(
            "http://example.com/users/123",
            "http://example.com/users/{id}"
        ));
        assert!(!uri_matches_template("ftp://test", "http://{host}"));
    }

    #[tokio::test]
    async fn test_resource_routing() {
        let mut registry = ResourceRegistry::new();
        let mut handler = MemoryResourceHandler::new("file:///{path}");
        handler.add_resource(
            "file:///test.txt",
            ResourceContent::text("file:///test.txt", "text/plain", "Hello"),
        );
        registry.register(handler).unwrap();

        let found = registry.match_uri("file:///test.txt");
        assert!(found.is_some());
    }

    #[test]
    fn resource_registry_rejects_resource_ids_beyond_manifest_capacity() {
        let mut registry = ResourceRegistry::new();

        for i in 0..CapabilityManifest::MAX_RESOURCES {
            let resource_id = registry
                .register(MemoryResourceHandler::new(format!("test://{i}/{{path}}")))
                .unwrap();
            assert_eq!(usize::from(resource_id), i);
        }

        let err = registry
            .register(MemoryResourceHandler::new("test://overflow/{path}"))
            .unwrap_err();

        assert!(matches!(
            err,
            ResourceError::CapacityExceeded {
                kind: "resource",
                ..
            }
        ));
        assert_eq!(registry.handler_count(), CapabilityManifest::MAX_RESOURCES);
    }
}

// ============================================================================
// Property 9: Subscription Notification
// **Validates: Requirements 4.5**
// For any resource with active subscriptions, when the resource changes,
// ALL subscribers SHALL receive a notification containing the resource URI.
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Feature: dcp-production, Property 9: Subscription Notification
    /// All subscribers should be notified when a resource changes.
    #[test]
    fn prop_subscription_notification(
        num_subscribers in 1usize..10
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut registry = ResourceRegistry::new();
            let handler = MemoryResourceHandler::new("file:///{path}").with_subscriptions();
            registry.register(handler).unwrap();

            let uri = "file:///test.txt";
            let notified_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

            // Subscribe multiple times
            let mut sub_ids = Vec::new();
            for _ in 0..num_subscribers {
                let count = std::sync::Arc::clone(&notified_count);
                let sub_id = registry.subscribe(uri, move |_| {
                    count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }).await.unwrap();
                sub_ids.push(sub_id);
            }

            prop_assert_eq!(registry.subscription_count(uri).await, num_subscribers,
                "Should have {} subscriptions", num_subscribers);

            // Notify change
            registry.notify_change(uri).await;

            // All subscribers should be notified
            prop_assert_eq!(notified_count.load(std::sync::atomic::Ordering::SeqCst), num_subscribers,
                "All {} subscribers should be notified", num_subscribers);

            Ok(())
        })?;
    }
}

// ============================================================================
// Property 10: Resource Pagination
// **Validates: Requirements 4.6**
// For any resource list with more items than the page size, pagination with
// cursor SHALL eventually return all items exactly once.
// ============================================================================

// Note: The current implementation doesn't have pagination across handlers,
// but we test that list_all returns all resources from all handlers.

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Feature: dcp-production, Property 10: Resource Pagination (all items returned)
    /// All registered resources should be returned in the list.
    #[test]
    fn prop_resource_pagination_all_items(
        num_resources in 1usize..20
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut registry = ResourceRegistry::new();
            let mut handler = MemoryResourceHandler::new("file:///{path}");

            // Add resources
            for i in 0..num_resources {
                let uri = format!("file:///resource{}.txt", i);
                handler.add_resource(&uri, ResourceContent::text(&uri, "text/plain", "content"));
            }
            registry.register(handler).unwrap();

            // List all
            let list = registry.list_all(None).unwrap();

            prop_assert_eq!(list.resources.len(), num_resources,
                "Should return all {} resources", num_resources);

            Ok(())
        })?;
    }
}
