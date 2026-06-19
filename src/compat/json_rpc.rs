//! JSON-RPC 2.0 parser for MCP compatibility.
//!
//! Provides parsing and formatting of JSON-RPC 2.0 messages for
//! translation between MCP and DCP protocols.

use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};
use std::collections::HashSet;
use std::fmt;
use thiserror::Error;

use crate::security::{sanitize_json_value, sanitize_text};

/// JSON-RPC 2.0 version string
pub const JSONRPC_VERSION: &str = "2.0";

/// Default maximum JSON-RPC request size for adapter entry points.
pub const DEFAULT_MAX_JSONRPC_REQUEST_SIZE: usize = 10 * 1024 * 1024;

/// Maximum accepted byte length for string request/response ids.
pub const MAX_JSONRPC_ID_STRING_BYTES: usize = 256;

/// JSON-RPC parsing errors
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum JsonRpcParseError {
    #[error("invalid JSON: {0}")]
    InvalidJson(String),
    #[error("missing jsonrpc field")]
    MissingVersion,
    #[error("invalid jsonrpc version: expected 2.0")]
    InvalidVersion,
    #[error("missing method field")]
    MissingMethod,
    #[error("missing id field")]
    MissingId,
    #[error("invalid request structure")]
    InvalidStructure,
    #[error("request too large")]
    RequestTooLarge,
    #[error("request id too large")]
    RequestIdTooLarge,
    #[error("request id contains sensitive data")]
    RequestIdSensitive,
    #[error("duplicate JSON object field")]
    DuplicateField,
    #[error("JSON-RPC batch requests are unsupported")]
    BatchUnsupported,
}

const DUPLICATE_FIELD_MESSAGE: &str = "duplicate JSON object field";
const REQUEST_ENVELOPE_FIELDS: &[&str] = &["jsonrpc", "method", "params", "id"];
const RESPONSE_ENVELOPE_FIELDS: &[&str] = &["jsonrpc", "result", "error", "id"];

struct DuplicateKeyDetector;

impl<'de> Deserialize<'de> for DuplicateKeyDetector {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(DuplicateKeyVisitor)
    }
}

struct DuplicateKeyVisitor;

impl<'de> Visitor<'de> for DuplicateKeyVisitor {
    type Value = DuplicateKeyDetector;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("any JSON value without duplicate object fields")
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E> {
        Ok(DuplicateKeyDetector)
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E> {
        Ok(DuplicateKeyDetector)
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E> {
        Ok(DuplicateKeyDetector)
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E> {
        Ok(DuplicateKeyDetector)
    }

    fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(DuplicateKeyDetector)
    }

    fn visit_string<E>(self, _value: String) -> Result<Self::Value, E> {
        Ok(DuplicateKeyDetector)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(DuplicateKeyDetector)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(DuplicateKeyDetector)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        DuplicateKeyDetector::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while seq.next_element::<DuplicateKeyDetector>()?.is_some() {}
        Ok(DuplicateKeyDetector)
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut seen = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key) {
                return Err(de::Error::custom(DUPLICATE_FIELD_MESSAGE));
            }
            map.next_value::<DuplicateKeyDetector>()?;
        }
        Ok(DuplicateKeyDetector)
    }
}

fn map_json_error(error: serde_json::Error) -> JsonRpcParseError {
    if error.to_string().contains(DUPLICATE_FIELD_MESSAGE) {
        JsonRpcParseError::DuplicateField
    } else {
        JsonRpcParseError::InvalidJson(error.to_string())
    }
}

fn ensure_no_duplicate_object_fields(json: &str) -> Result<(), JsonRpcParseError> {
    let mut deserializer = serde_json::Deserializer::from_str(json);
    DuplicateKeyDetector::deserialize(&mut deserializer).map_err(map_json_error)?;
    deserializer.end().map_err(map_json_error)
}

fn ensure_only_known_fields(
    obj: &Map<String, Value>,
    allowed: &[&str],
) -> Result<(), JsonRpcParseError> {
    if obj.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(JsonRpcParseError::InvalidStructure);
    }

    Ok(())
}

fn validate_request_id(id: &RequestId) -> Result<(), JsonRpcParseError> {
    if let RequestId::String(id) = id {
        if id.len() > MAX_JSONRPC_ID_STRING_BYTES {
            return Err(JsonRpcParseError::RequestIdTooLarge);
        }
        if sanitize_text(id) != *id {
            return Err(JsonRpcParseError::RequestIdSensitive);
        }
    }

    Ok(())
}

fn validate_method_name(method: &str) -> Result<(), JsonRpcParseError> {
    if method.is_empty() || method.starts_with("rpc.") || method.chars().any(char::is_control) {
        return Err(JsonRpcParseError::InvalidStructure);
    }

    Ok(())
}

fn validate_response_shape(response: &JsonRpcResponse) -> Result<(), JsonRpcParseError> {
    if response.jsonrpc != JSONRPC_VERSION {
        return Err(JsonRpcParseError::InvalidVersion);
    }

    if matches!(response.id, RequestId::Missing) {
        return Err(JsonRpcParseError::MissingId);
    }

    if response.result.is_some() == response.error.is_some() {
        return Err(JsonRpcParseError::InvalidStructure);
    }

    validate_request_id(&response.id)
}

fn parse_request_id_value(
    value: Option<&Value>,
    missing_id: RequestId,
) -> Result<RequestId, JsonRpcParseError> {
    let id = match value {
        Some(Value::String(s)) => RequestId::String(s.clone()),
        Some(Value::Number(n)) => {
            if let Some(i) = n.as_i64() {
                RequestId::Number(i)
            } else {
                return Err(JsonRpcParseError::InvalidStructure);
            }
        }
        Some(Value::Null) => RequestId::Null,
        None => missing_id,
        _ => return Err(JsonRpcParseError::InvalidStructure),
    };

    validate_request_id(&id)?;
    Ok(id)
}

/// JSON-RPC request ID (can be string, number, or null)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(untagged)]
pub enum RequestId {
    String(String),
    Number(i64),
    Null,
    #[default]
    Missing,
}

impl RequestId {
    /// Parse and validate a JSON-RPC request id from a JSON value.
    pub fn try_from_json_value(value: &Value) -> Result<Self, JsonRpcParseError> {
        parse_request_id_value(Some(value), RequestId::Missing)
    }
}

/// JSON-RPC 2.0 request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    /// JSON-RPC version (must be "2.0")
    pub jsonrpc: String,
    /// Method name
    pub method: String,
    /// Request parameters (optional)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
    /// Request ID (optional for notifications)
    #[serde(default, skip_serializing_if = "is_missing_id")]
    pub id: RequestId,
}

fn is_missing_id(id: &RequestId) -> bool {
    matches!(id, RequestId::Missing)
}

impl JsonRpcRequest {
    /// Create a new request
    pub fn new(method: impl Into<String>, params: Option<Value>, id: RequestId) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            method: method.into(),
            params,
            id,
        }
    }

    /// Create a notification (no id)
    pub fn notification(method: impl Into<String>, params: Option<Value>) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            method: method.into(),
            params,
            id: RequestId::Missing,
        }
    }

    /// Check if this is a notification (no id)
    pub fn is_notification(&self) -> bool {
        matches!(self.id, RequestId::Missing)
    }

    /// Get params as a specific type
    pub fn params_as<T: for<'de> Deserialize<'de>>(&self) -> Option<T> {
        self.params
            .as_ref()
            .and_then(|p| serde_json::from_value(p.clone()).ok())
    }
}

/// JSON-RPC 2.0 response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    /// JSON-RPC version (must be "2.0")
    pub jsonrpc: String,
    /// Result (present on success)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// Error (present on failure)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
    /// Request ID
    pub id: RequestId,
}

impl JsonRpcResponse {
    /// Create a success response
    pub fn success(id: RequestId, result: Value) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            result: Some(result),
            error: None,
            id,
        }
    }

    /// Create an error response
    pub fn error(id: RequestId, error: JsonRpcError) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            result: None,
            error: Some(error),
            id,
        }
    }

    /// Check if this is a success response
    pub fn is_success(&self) -> bool {
        self.result.is_some() && self.error.is_none()
    }

    /// Check if this is an error response
    pub fn is_error(&self) -> bool {
        self.error.is_some()
    }
}

/// JSON-RPC 2.0 error object
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JsonRpcError {
    /// Error code
    pub code: i32,
    /// Error message
    pub message: String,
    /// Additional error data (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl JsonRpcError {
    /// Create a new error
    pub fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: sanitize_text(&message.into()),
            data: None,
        }
    }

    /// Create an error with data
    pub fn with_data(code: i32, message: impl Into<String>, data: Value) -> Self {
        Self {
            code,
            message: sanitize_text(&message.into()),
            data: Some(sanitize_json_value(&data)),
        }
    }

    // Standard JSON-RPC error codes

    /// Parse error (-32700)
    pub fn parse_error() -> Self {
        Self::new(-32700, "Parse error")
    }

    /// Invalid request (-32600)
    pub fn invalid_request() -> Self {
        Self::new(-32600, "Invalid Request")
    }

    /// Method not found (-32601)
    pub fn method_not_found() -> Self {
        Self::new(-32601, "Method not found")
    }

    /// Invalid params (-32602)
    pub fn invalid_params() -> Self {
        Self::new(-32602, "Invalid params")
    }

    /// Internal error (-32603)
    pub fn internal_error() -> Self {
        Self::new(-32603, "Internal error")
    }
}

/// JSON-RPC parser
pub struct JsonRpcParser;

impl JsonRpcParser {
    /// Parse a JSON-RPC request from a string
    pub fn parse_request(json: &str) -> Result<JsonRpcRequest, JsonRpcParseError> {
        Self::parse_request_with_limit(json, DEFAULT_MAX_JSONRPC_REQUEST_SIZE)
    }

    /// Parse a JSON-RPC request from a string with a maximum byte size.
    pub fn parse_request_with_limit(
        json: &str,
        max_size: usize,
    ) -> Result<JsonRpcRequest, JsonRpcParseError> {
        if json.len() > max_size {
            return Err(JsonRpcParseError::RequestTooLarge);
        }

        ensure_no_duplicate_object_fields(json)?;

        let value: Value = serde_json::from_str(json).map_err(map_json_error)?;

        Self::parse_request_value(&value)
    }

    /// Parse a JSON-RPC request from a Value
    pub fn parse_request_value(value: &Value) -> Result<JsonRpcRequest, JsonRpcParseError> {
        if value.is_array() {
            return Err(JsonRpcParseError::BatchUnsupported);
        }

        let obj = value
            .as_object()
            .ok_or(JsonRpcParseError::InvalidStructure)?;
        ensure_only_known_fields(obj, REQUEST_ENVELOPE_FIELDS)?;

        // Check jsonrpc version
        let version = obj
            .get("jsonrpc")
            .and_then(|v| v.as_str())
            .ok_or(JsonRpcParseError::MissingVersion)?;

        if version != JSONRPC_VERSION {
            return Err(JsonRpcParseError::InvalidVersion);
        }

        // Get method
        let method = obj
            .get("method")
            .and_then(|v| v.as_str())
            .ok_or(JsonRpcParseError::MissingMethod)?
            .to_string();

        validate_method_name(&method)?;

        if obj.contains_key("result") || obj.contains_key("error") {
            return Err(JsonRpcParseError::InvalidStructure);
        }

        // Get params (optional)
        let params = obj.get("params").cloned();
        if let Some(params) = &params {
            if !(params.is_object() || params.is_array()) {
                return Err(JsonRpcParseError::InvalidStructure);
            }
        }

        // Get id (optional for notifications)
        let id = parse_request_id_value(obj.get("id"), RequestId::Missing)?;

        Ok(JsonRpcRequest {
            jsonrpc: JSONRPC_VERSION.to_string(),
            method,
            params,
            id,
        })
    }

    /// Parse a JSON-RPC response from a string
    pub fn parse_response(json: &str) -> Result<JsonRpcResponse, JsonRpcParseError> {
        Self::parse_response_with_limit(json, DEFAULT_MAX_JSONRPC_REQUEST_SIZE)
    }

    /// Parse a JSON-RPC response from a string with a maximum byte size.
    pub fn parse_response_with_limit(
        json: &str,
        max_size: usize,
    ) -> Result<JsonRpcResponse, JsonRpcParseError> {
        if json.len() > max_size {
            return Err(JsonRpcParseError::RequestTooLarge);
        }

        ensure_no_duplicate_object_fields(json)?;

        let value: Value = serde_json::from_str(json).map_err(map_json_error)?;

        Self::parse_response_value(&value)
    }

    /// Parse a JSON-RPC response from a Value
    pub fn parse_response_value(value: &Value) -> Result<JsonRpcResponse, JsonRpcParseError> {
        let obj = value
            .as_object()
            .ok_or(JsonRpcParseError::InvalidStructure)?;
        ensure_only_known_fields(obj, RESPONSE_ENVELOPE_FIELDS)?;

        // Check jsonrpc version
        let version = obj
            .get("jsonrpc")
            .and_then(|v| v.as_str())
            .ok_or(JsonRpcParseError::MissingVersion)?;

        if version != JSONRPC_VERSION {
            return Err(JsonRpcParseError::InvalidVersion);
        }

        if obj.contains_key("method") || obj.contains_key("params") {
            return Err(JsonRpcParseError::InvalidStructure);
        }

        // Get id
        let id = parse_request_id_value(obj.get("id"), RequestId::Missing)?;
        if matches!(id, RequestId::Missing) {
            return Err(JsonRpcParseError::MissingId);
        }

        // Get result or error
        let result = obj.get("result").cloned();
        let error = obj
            .get("error")
            .map(|e| serde_json::from_value(e.clone()))
            .transpose()
            .map_err(|_| JsonRpcParseError::InvalidStructure)?;

        if result.is_some() == error.is_some() {
            return Err(JsonRpcParseError::InvalidStructure);
        }

        Ok(JsonRpcResponse {
            jsonrpc: JSONRPC_VERSION.to_string(),
            result,
            error,
            id,
        })
    }

    /// Format a request to JSON string
    pub fn format_request(request: &JsonRpcRequest) -> Result<String, JsonRpcParseError> {
        if request.jsonrpc != JSONRPC_VERSION {
            return Err(JsonRpcParseError::InvalidVersion);
        }
        validate_method_name(&request.method)?;
        validate_request_id(&request.id)?;
        serde_json::to_string(request).map_err(|e| JsonRpcParseError::InvalidJson(e.to_string()))
    }

    /// Format a response to JSON string
    pub fn format_response(response: &JsonRpcResponse) -> Result<String, JsonRpcParseError> {
        validate_response_shape(response)?;
        let mut response = response.clone();
        if let Some(error) = &mut response.error {
            error.message = sanitize_text(&error.message);
            error.data = error.data.as_ref().map(sanitize_json_value);
        }

        serde_json::to_string(&response).map_err(|e| JsonRpcParseError::InvalidJson(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_request() {
        let json = r#"{"jsonrpc":"2.0","method":"test","params":{"foo":"bar"},"id":1}"#;
        let request = JsonRpcParser::parse_request(json).unwrap();

        assert_eq!(request.jsonrpc, "2.0");
        assert_eq!(request.method, "test");
        assert_eq!(request.id, RequestId::Number(1));
        assert!(request.params.is_some());
    }

    #[test]
    fn test_parse_notification() {
        let json = r#"{"jsonrpc":"2.0","method":"notify","params":{}}"#;
        let request = JsonRpcParser::parse_request(json).unwrap();

        assert_eq!(request.method, "notify");
        assert!(request.is_notification());
    }

    #[test]
    fn test_parse_request_string_id() {
        let json = r#"{"jsonrpc":"2.0","method":"test","id":"abc-123"}"#;
        let request = JsonRpcParser::parse_request(json).unwrap();

        assert_eq!(request.id, RequestId::String("abc-123".to_string()));
    }

    #[test]
    fn test_parse_invalid_version() {
        let json = r#"{"jsonrpc":"1.0","method":"test","id":1}"#;
        let result = JsonRpcParser::parse_request(json);

        assert!(matches!(result, Err(JsonRpcParseError::InvalidVersion)));
    }

    #[test]
    fn test_parse_missing_method() {
        let json = r#"{"jsonrpc":"2.0","id":1}"#;
        let result = JsonRpcParser::parse_request(json);

        assert!(matches!(result, Err(JsonRpcParseError::MissingMethod)));
    }

    #[test]
    fn test_format_request() {
        let request = JsonRpcRequest::new(
            "test",
            Some(serde_json::json!({"a": 1})),
            RequestId::Number(42),
        );
        let json = JsonRpcParser::format_request(&request).unwrap();

        // Parse it back
        let parsed = JsonRpcParser::parse_request(&json).unwrap();
        assert_eq!(parsed.method, "test");
        assert_eq!(parsed.id, RequestId::Number(42));
    }

    #[test]
    fn test_success_response() {
        let response =
            JsonRpcResponse::success(RequestId::Number(1), serde_json::json!({"result": "ok"}));

        assert!(response.is_success());
        assert!(!response.is_error());

        let json = JsonRpcParser::format_response(&response).unwrap();
        let parsed = JsonRpcParser::parse_response(&json).unwrap();

        assert!(parsed.is_success());
        assert_eq!(parsed.id, RequestId::Number(1));
    }

    #[test]
    fn test_error_response() {
        let response =
            JsonRpcResponse::error(RequestId::Number(1), JsonRpcError::method_not_found());

        assert!(response.is_error());
        assert!(!response.is_success());

        let json = JsonRpcParser::format_response(&response).unwrap();
        let parsed = JsonRpcParser::parse_response(&json).unwrap();

        assert!(parsed.is_error());
        assert_eq!(parsed.error.unwrap().code, -32601);
    }

    #[test]
    fn test_error_codes() {
        assert_eq!(JsonRpcError::parse_error().code, -32700);
        assert_eq!(JsonRpcError::invalid_request().code, -32600);
        assert_eq!(JsonRpcError::method_not_found().code, -32601);
        assert_eq!(JsonRpcError::invalid_params().code, -32602);
        assert_eq!(JsonRpcError::internal_error().code, -32603);
    }

    #[test]
    fn test_request_round_trip() {
        let original = JsonRpcRequest::new(
            "tools/call",
            Some(serde_json::json!({
                "name": "read_file",
                "arguments": {"path": "/tmp/test.txt"}
            })),
            RequestId::String("req-001".to_string()),
        );

        let json = JsonRpcParser::format_request(&original).unwrap();
        let parsed = JsonRpcParser::parse_request(&json).unwrap();

        assert_eq!(parsed.method, original.method);
        assert_eq!(parsed.id, original.id);
        assert_eq!(parsed.params, original.params);
    }

    #[test]
    fn test_response_round_trip() {
        let original = JsonRpcResponse::success(
            RequestId::Number(123),
            serde_json::json!({
                "content": [{"type": "text", "text": "Hello"}]
            }),
        );

        let json = JsonRpcParser::format_response(&original).unwrap();
        let parsed = JsonRpcParser::parse_response(&json).unwrap();

        assert_eq!(parsed.id, original.id);
        assert_eq!(parsed.result, original.result);
    }
}
