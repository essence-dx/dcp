//! MCP to DCP adapter for backward compatibility.
//!
//! Translates JSON-RPC 2.0 MCP messages to DCP binary format and back.

use std::collections::HashMap;
use std::sync::Mutex;

use serde_json::Value;

use crate::dispatch::{BinaryTrieRouter, ToolResult};
use crate::security::{SecurityAuditAction, SecurityAuditEvent, SecurityAuditLog};
use crate::{CapabilityManifest, DCPError, SecurityError};

use super::json_rpc::{
    JsonRpcError, JsonRpcParseError, JsonRpcParser, JsonRpcRequest, JsonRpcResponse, RequestId,
    DEFAULT_MAX_JSONRPC_REQUEST_SIZE,
};
use super::request_replay::{replay_key, RequestReplayGuard};

/// Adapter errors
#[derive(Debug, Clone, thiserror::Error)]
pub enum AdapterError {
    #[error("JSON-RPC parse error: {0}")]
    ParseError(#[from] JsonRpcParseError),
    #[error("unknown tool")]
    UnknownTool(String),
    #[error("DCP error: {0}")]
    DcpError(#[from] DCPError),
    #[error("serialization error: {0}")]
    SerializationError(String),
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("invalid params: {0}")]
    InvalidParams(String),
    #[error("{kind} capacity exceeded")]
    CapacityExceeded { kind: &'static str, max: usize },
}

/// MCP to DCP adapter
pub struct McpAdapter {
    /// Tool name to ID cache
    tool_cache: HashMap<String, u16>,
    /// ID to tool name reverse mapping
    id_to_name: HashMap<u16, String>,
    /// Maximum accepted JSON-RPC request size in bytes.
    max_request_size: usize,
    /// Negotiated capabilities for legacy execution entry points.
    negotiated_capabilities: Option<CapabilityManifest>,
    /// Structured security audit receipts.
    security_audit: SecurityAuditLog,
    /// Replay guard for side-effecting legacy tools/call request ids.
    tool_call_replay_guard: Mutex<RequestReplayGuard>,
}

impl McpAdapter {
    /// Create a new adapter
    pub fn new() -> Self {
        Self {
            tool_cache: HashMap::new(),
            id_to_name: HashMap::new(),
            max_request_size: DEFAULT_MAX_JSONRPC_REQUEST_SIZE,
            negotiated_capabilities: None,
            security_audit: SecurityAuditLog::new(),
            tool_call_replay_guard: Mutex::new(RequestReplayGuard::default()),
        }
    }

    /// Set maximum JSON-RPC request size for adapter entry points.
    pub fn with_max_request_size(mut self, max_request_size: usize) -> Self {
        self.max_request_size = max_request_size;
        self
    }

    /// Set the negotiated capability manifest for legacy adapter execution.
    pub fn with_negotiated_capabilities(mut self, capabilities: CapabilityManifest) -> Self {
        self.negotiated_capabilities = Some(capabilities);
        self
    }

    fn request_id_for_audit(id: &RequestId) -> Option<String> {
        match id {
            RequestId::String(value) => Some(value.clone()),
            RequestId::Number(value) => Some(value.to_string()),
            RequestId::Null => Some("null".to_string()),
            RequestId::Missing => None,
        }
    }

    fn audit_capability_denial(&self, request: &JsonRpcRequest) {
        let mut event =
            SecurityAuditEvent::new(SecurityAuditAction::CapabilityDenied, "capability_denied")
                .with_method(request.method.clone())
                .with_field("adapter", "legacy_mcp");
        if let Some(request_id) = Self::request_id_for_audit(&request.id) {
            event = event.with_request_id(request_id);
        }
        self.security_audit.record(event);
    }

    fn audit_request_rejection(
        &self,
        action: SecurityAuditAction,
        reason: &'static str,
        request: &JsonRpcRequest,
    ) {
        let mut event = SecurityAuditEvent::new(action, reason)
            .with_method(request.method.clone())
            .with_field("adapter", "legacy_mcp");
        if let Some(request_id) = Self::request_id_for_audit(&request.id) {
            event = event.with_request_id(request_id);
        }
        self.security_audit.record(event);
    }

    fn capability_denied_response(&self, request: &JsonRpcRequest) -> Result<String, AdapterError> {
        self.audit_capability_denial(request);
        self.format_error_response(
            request.id.clone(),
            JsonRpcError::new(-32001, "Capability denied"),
        )
    }

    fn replay_rejected_response(&self, request: &JsonRpcRequest) -> Result<String, AdapterError> {
        self.audit_request_rejection(
            SecurityAuditAction::ReplayRejected,
            "request_replay",
            request,
        );
        self.format_error_response(
            request.id.clone(),
            JsonRpcError::new(-32002, "Request replay rejected"),
        )
    }

    fn record_tool_call_request_id(&self, request: &JsonRpcRequest) -> Result<bool, AdapterError> {
        let Some(request_id) = Self::request_id_for_audit(&request.id) else {
            return Ok(true);
        };
        let mut guard = self
            .tool_call_replay_guard
            .lock()
            .map_err(|_| AdapterError::InvalidRequest("request replay guard unavailable".into()))?;

        Ok(guard.check_and_record(replay_key("tools/call", &request_id)))
    }

    fn security_error_response(
        &self,
        request: &JsonRpcRequest,
        error: SecurityError,
    ) -> Result<String, AdapterError> {
        match error {
            SecurityError::ValidationFailed => self.validation_error_response(
                Some(request),
                &AdapterError::InvalidParams("schema validation failed".into()),
            ),
            _ => self.capability_denied_response(request),
        }
    }

    fn audit_tool_registration_failure(&self, reason: &'static str, tool_id: u16, name: &str) {
        self.security_audit.record(
            SecurityAuditEvent::new(SecurityAuditAction::ValidationRejected, reason)
                .with_field("adapter", "legacy_mcp")
                .with_field("operation", "tool_registration")
                .with_field("tool_id", tool_id.to_string())
                .with_field("tool_name", name),
        );
    }

    fn validation_error_details(error: &AdapterError) -> (&'static str, JsonRpcError) {
        match error {
            AdapterError::ParseError(JsonRpcParseError::InvalidJson(_)) => {
                ("parse_error", JsonRpcError::parse_error())
            }
            AdapterError::ParseError(JsonRpcParseError::RequestTooLarge) => {
                ("request_too_large", JsonRpcError::invalid_request())
            }
            AdapterError::ParseError(JsonRpcParseError::RequestIdTooLarge) => {
                ("request_id_too_large", JsonRpcError::invalid_request())
            }
            AdapterError::ParseError(JsonRpcParseError::RequestIdSensitive) => {
                ("request_id_sensitive", JsonRpcError::invalid_request())
            }
            AdapterError::ParseError(JsonRpcParseError::BatchUnsupported) => {
                ("batch_unsupported", JsonRpcError::invalid_request())
            }
            AdapterError::InvalidParams(_) => ("invalid_params", JsonRpcError::invalid_params()),
            AdapterError::ParseError(_) | AdapterError::InvalidRequest(_) => {
                ("invalid_request", JsonRpcError::invalid_request())
            }
            _ => ("request_failed", JsonRpcError::internal_error()),
        }
    }

    fn validation_error_response(
        &self,
        request: Option<&JsonRpcRequest>,
        error: &AdapterError,
    ) -> Result<String, AdapterError> {
        let (reason, json_error) = Self::validation_error_details(error);
        let mut event = SecurityAuditEvent::new(SecurityAuditAction::ValidationRejected, reason)
            .with_field("adapter", "legacy_mcp");

        let response_id = match request {
            Some(request) => {
                event = event.with_method(request.method.clone());
                if let Some(request_id) = Self::request_id_for_audit(&request.id) {
                    event = event.with_request_id(request_id);
                }
                match &request.id {
                    RequestId::Missing => RequestId::Null,
                    _ => request.id.clone(),
                }
            }
            None => RequestId::Null,
        };

        self.security_audit.record(event);
        self.format_error_response(response_id, json_error)
    }

    fn require_request_method_response(
        &self,
        request: &JsonRpcRequest,
        expected_method: &'static str,
    ) -> Option<Result<String, AdapterError>> {
        if request.method == expected_method && !request.is_notification() {
            return None;
        }

        Some(self.validation_error_response(
            Some(request),
            &AdapterError::InvalidRequest(format!(
                "{expected_method} requires a JSON-RPC request id"
            )),
        ))
    }

    /// Register a tool mapping
    pub fn register_tool(
        &mut self,
        name: impl Into<String>,
        tool_id: u16,
    ) -> Result<u16, AdapterError> {
        let name = name.into();
        if (tool_id as usize) >= CapabilityManifest::MAX_TOOLS {
            self.audit_tool_registration_failure(
                "tool_registration_capacity_exceeded",
                tool_id,
                &name,
            );
            return Err(AdapterError::CapacityExceeded {
                kind: "tool",
                max: CapabilityManifest::MAX_TOOLS,
            });
        }
        if self.tool_cache.contains_key(&name) {
            self.audit_tool_registration_failure(
                "tool_registration_duplicate_name",
                tool_id,
                &name,
            );
            return Err(AdapterError::InvalidRequest("duplicate tool name".into()));
        }
        if self.id_to_name.contains_key(&tool_id) {
            self.audit_tool_registration_failure("tool_registration_duplicate_id", tool_id, &name);
            return Err(AdapterError::InvalidRequest("duplicate tool id".into()));
        }

        self.tool_cache.insert(name.clone(), tool_id);
        self.id_to_name.insert(tool_id, name);
        Ok(tool_id)
    }

    /// Resolve MCP tool name to DCP tool_id
    pub fn resolve_tool_name(&self, name: &str) -> Option<u16> {
        self.tool_cache.get(name).copied()
    }

    /// Resolve DCP tool_id to MCP tool name
    pub fn resolve_tool_id(&self, tool_id: u16) -> Option<&str> {
        self.id_to_name.get(&tool_id).map(|s| s.as_str())
    }

    /// Get structured security audit receipts.
    pub fn security_audit(&self) -> SecurityAuditLog {
        self.security_audit.clone()
    }

    /// Parse an MCP JSON-RPC request
    pub fn parse_request(&self, json: &str) -> Result<JsonRpcRequest, AdapterError> {
        Ok(JsonRpcParser::parse_request_with_limit(
            json,
            self.max_request_size,
        )?)
    }

    /// Translate MCP request params to DCP arguments
    pub fn translate_params(&self, params: &Option<Value>) -> Vec<u8> {
        match params {
            Some(value) => {
                // For now, serialize params as JSON bytes
                // In a full implementation, this would convert to binary format
                serde_json::to_vec(value).unwrap_or_default()
            }
            None => Vec::new(),
        }
    }

    fn translate_legacy_tool_arguments(
        &self,
        arguments: Option<&Value>,
    ) -> Result<Vec<u8>, AdapterError> {
        match arguments {
            None => Ok(Vec::new()),
            Some(Value::Object(arguments)) if arguments.is_empty() => Ok(Vec::new()),
            Some(Value::Object(_)) => Err(AdapterError::InvalidParams(
                "legacy tools/call arguments must be empty or omitted".into(),
            )),
            Some(_) => Err(AdapterError::InvalidParams(
                "tools/call arguments must be an object".into(),
            )),
        }
    }

    fn tools_call_params_object<'a>(
        &self,
        params: &'a Value,
    ) -> Result<&'a serde_json::Map<String, Value>, AdapterError> {
        let params = params.as_object().ok_or_else(|| {
            AdapterError::InvalidParams("tools/call params must be an object".into())
        })?;

        if params
            .keys()
            .any(|key| key != "name" && key != "arguments" && key != "_meta")
        {
            return Err(AdapterError::InvalidParams(
                "tools/call params contain unsupported fields".into(),
            ));
        }
        if params.get("_meta").is_some_and(|meta| !meta.is_object()) {
            return Err(AdapterError::InvalidParams(
                "tools/call _meta must be an object".into(),
            ));
        }

        Ok(params)
    }

    /// Translate DCP result to MCP response value
    pub fn translate_result(&self, result: &ToolResult) -> Value {
        match result {
            ToolResult::Success(data) => {
                // Try to parse as JSON, otherwise return as string
                serde_json::from_slice(data)
                    .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(data).to_string()))
            }
            ToolResult::Empty => Value::Null,
            ToolResult::Error(err) => {
                serde_json::json!({
                    "error": {
                        "code": *err as i32,
                        "message": err.to_string()
                    }
                })
            }
        }
    }

    /// Format a success response
    pub fn format_success_response(
        &self,
        id: RequestId,
        result: Value,
    ) -> Result<String, AdapterError> {
        let response = JsonRpcResponse::success(id, result);
        JsonRpcParser::format_response(&response)
            .map_err(|e| AdapterError::SerializationError(e.to_string()))
    }

    /// Format an error response
    pub fn format_error_response(
        &self,
        id: RequestId,
        error: JsonRpcError,
    ) -> Result<String, AdapterError> {
        let response = JsonRpcResponse::error(id, error);
        JsonRpcParser::format_response(&response)
            .map_err(|e| AdapterError::SerializationError(e.to_string()))
    }

    /// Handle an MCP initialize request
    pub fn handle_initialize(&self, request: &JsonRpcRequest) -> Result<String, AdapterError> {
        if let Some(response) = self.require_request_method_response(request, "initialize") {
            return response;
        }

        let mut capabilities = serde_json::Map::new();
        if !self.tool_cache.is_empty() {
            capabilities.insert(
                "tools".to_string(),
                serde_json::json!({
                    "listChanged": false
                }),
            );
        }

        let result = serde_json::json!({
            "protocolVersion": "2024-11-05",
            "capabilities": capabilities,
            "serverInfo": {
                "name": "dcp-server",
                "version": "0.1.0"
            }
        });

        self.format_success_response(request.id.clone(), result)
    }

    /// Handle an MCP tools/list request
    pub fn handle_tools_list(&self, request: &JsonRpcRequest) -> Result<String, AdapterError> {
        if let Some(response) = self.require_request_method_response(request, "tools/list") {
            return response;
        }

        let capabilities = match self.negotiated_capabilities.as_ref() {
            Some(capabilities) if capabilities.tool_count() > 0 => capabilities,
            _ => return self.capability_denied_response(request),
        };

        let tools: Vec<Value> = self
            .tool_cache
            .iter()
            .filter(|(_, tool_id)| capabilities.has_tool(**tool_id))
            .map(|(name, _)| {
                serde_json::json!({
                    "name": name,
                    "description": format!("Tool: {}", name),
                    "inputSchema": {
                        "type": "object",
                        "properties": {}
                    }
                })
            })
            .collect();

        let result = serde_json::json!({
            "tools": tools
        });

        self.format_success_response(request.id.clone(), result)
    }

    /// Handle an MCP tools/call request
    pub fn handle_tools_call(
        &self,
        request: &JsonRpcRequest,
        router: &BinaryTrieRouter,
    ) -> Result<String, AdapterError> {
        if let Some(response) = self.require_request_method_response(request, "tools/call") {
            return response;
        }

        // Extract tool name and arguments from params
        let params_value = match request.params.as_ref() {
            Some(params) => params,
            None => {
                return self.validation_error_response(
                    Some(request),
                    &AdapterError::ParseError(JsonRpcParseError::InvalidStructure),
                );
            }
        };
        let params = match self.tools_call_params_object(params_value) {
            Ok(params) => params,
            Err(err) => return self.validation_error_response(Some(request), &err),
        };

        let tool_name = match params.get("name").and_then(|v| v.as_str()) {
            Some(name) => name,
            None => {
                return self.validation_error_response(
                    Some(request),
                    &AdapterError::ParseError(JsonRpcParseError::InvalidStructure),
                );
            }
        };

        let arguments = params.get("arguments");

        // Resolve tool name to ID
        let tool_id = match self.resolve_tool_name(tool_name) {
            Some(tool_id) => tool_id,
            None => return self.capability_denied_response(request),
        };
        let capabilities = match self.negotiated_capabilities.as_ref() {
            Some(capabilities) => capabilities,
            None => return self.capability_denied_response(request),
        };

        // Execute via router
        let args_bytes = match self.translate_legacy_tool_arguments(arguments) {
            Ok(args_bytes) => args_bytes,
            Err(err) => return self.validation_error_response(Some(request), &err),
        };
        if !self.record_tool_call_request_id(request)? {
            return self.replay_rejected_response(request);
        }

        let shared_args = crate::dispatch::SharedArgs::new(&args_bytes, 0);

        let result = match router.execute_authorized(capabilities, tool_id, &shared_args) {
            Ok(result) => result,
            Err(err) => return self.security_error_response(request, err),
        };

        // Translate result
        let result_value = self.translate_result(&result);

        // Format MCP response
        let response_result = serde_json::json!({
            "content": [{
                "type": "text",
                "text": serde_json::to_string(&result_value).unwrap_or_default()
            }]
        });

        self.format_success_response(request.id.clone(), response_result)
    }

    /// Handle a generic MCP request
    pub fn handle_request(
        &self,
        json: &str,
        router: &BinaryTrieRouter,
    ) -> Result<String, AdapterError> {
        let request = match self.parse_request(json) {
            Ok(request) => request,
            Err(error) => return self.validation_error_response(None, &error),
        };

        if request.is_notification() {
            self.audit_request_rejection(
                SecurityAuditAction::RequestRejected,
                "notification_not_allowed",
                &request,
            );
            return self.format_error_response(RequestId::Null, JsonRpcError::invalid_request());
        }

        let response = match request.method.as_str() {
            "initialize" => self.handle_initialize(&request),
            "tools/list" => self.handle_tools_list(&request),
            "tools/call" => self.handle_tools_call(&request, router),
            _ => {
                // Unknown method
                self.audit_request_rejection(
                    SecurityAuditAction::RequestRejected,
                    "method_not_found",
                    &request,
                );
                self.format_error_response(request.id.clone(), JsonRpcError::method_not_found())
            }
        };

        match response {
            Err(error @ AdapterError::ParseError(_))
            | Err(error @ AdapterError::InvalidRequest(_)) => {
                self.validation_error_response(Some(&request), &error)
            }
            other => other,
        }
    }

    /// Get the number of registered tools
    pub fn tool_count(&self) -> usize {
        self.tool_cache.len()
    }
}

impl Default for McpAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_tool() {
        let mut adapter = McpAdapter::new();
        adapter.register_tool("read_file", 1).unwrap();
        adapter.register_tool("write_file", 2).unwrap();

        assert_eq!(adapter.resolve_tool_name("read_file"), Some(1));
        assert_eq!(adapter.resolve_tool_name("write_file"), Some(2));
        assert_eq!(adapter.resolve_tool_name("unknown"), None);

        assert_eq!(adapter.resolve_tool_id(1), Some("read_file"));
        assert_eq!(adapter.resolve_tool_id(2), Some("write_file"));
        assert_eq!(adapter.resolve_tool_id(99), None);
    }

    #[test]
    fn test_parse_request() {
        let adapter = McpAdapter::new();
        let json = r#"{"jsonrpc":"2.0","method":"initialize","id":1}"#;

        let request = adapter.parse_request(json).unwrap();
        assert_eq!(request.method, "initialize");
    }

    #[test]
    fn test_translate_params() {
        let adapter = McpAdapter::new();

        let params = Some(serde_json::json!({"path": "/tmp/test.txt"}));
        let bytes = adapter.translate_params(&params);

        assert!(!bytes.is_empty());
        let parsed: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed["path"], "/tmp/test.txt");
    }

    #[test]
    fn test_translate_result_success() {
        let adapter = McpAdapter::new();

        let result = ToolResult::Success(b"hello world".to_vec());
        let value = adapter.translate_result(&result);

        assert_eq!(value, Value::String("hello world".to_string()));
    }

    #[test]
    fn test_translate_result_json() {
        let adapter = McpAdapter::new();

        let json_bytes = serde_json::to_vec(&serde_json::json!({"key": "value"})).unwrap();
        let result = ToolResult::Success(json_bytes);
        let value = adapter.translate_result(&result);

        assert_eq!(value["key"], "value");
    }

    #[test]
    fn test_translate_result_error() {
        let adapter = McpAdapter::new();

        let result = ToolResult::Error(DCPError::ToolNotFound);
        let value = adapter.translate_result(&result);

        assert_eq!(value["error"]["code"], DCPError::ToolNotFound as i32);
        assert!(value["error"]["message"]
            .as_str()
            .unwrap()
            .contains("not found"));
    }

    #[test]
    fn test_handle_initialize() {
        let adapter = McpAdapter::new();
        let request = JsonRpcRequest::new("initialize", None, RequestId::Number(1));

        let response_json = adapter.handle_initialize(&request).unwrap();
        let response = JsonRpcParser::parse_response(&response_json).unwrap();

        assert!(response.is_success());
        let result = response.result.unwrap();
        assert!(result["capabilities"].is_object());
        assert!(result["capabilities"]["tools"].is_null());
    }

    #[test]
    fn test_handle_tools_list() {
        let mut adapter = McpAdapter::new();
        adapter.register_tool("read_file", 1).unwrap();
        adapter.register_tool("write_file", 2).unwrap();
        let mut capabilities = CapabilityManifest::new(1);
        capabilities.set_tool(1);
        capabilities.set_tool(2);
        let adapter = adapter.with_negotiated_capabilities(capabilities);

        let request = JsonRpcRequest::new("tools/list", None, RequestId::Number(1));
        let response_json = adapter.handle_tools_list(&request).unwrap();
        let response = JsonRpcParser::parse_response(&response_json).unwrap();

        assert!(response.is_success());
        let result = response.result.unwrap();
        let tools = result["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 2);
    }

    #[test]
    fn test_format_error_response() {
        let adapter = McpAdapter::new();

        let response = adapter
            .format_error_response(RequestId::Number(1), JsonRpcError::method_not_found())
            .unwrap();

        let parsed = JsonRpcParser::parse_response(&response).unwrap();
        assert!(parsed.is_error());
        assert_eq!(parsed.error.unwrap().code, -32601);
    }
}
