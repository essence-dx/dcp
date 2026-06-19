//! Complete MCP adapter with full protocol support.
//!
//! Supports all MCP methods: tools, resources, prompts, logging, sampling, completion.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use serde_json::{Map, Value};
use tokio::sync::RwLock;

use crate::binary::ArgType;
use crate::dispatch::{BinaryTrieRouter, SharedArgs, ToolResult};
use crate::protocol::{FieldDef, InputSchema};
use crate::resource::{ResourceContent, ResourceError, ResourceRegistry};
use crate::security::{sanitize_text, SecurityAuditAction, SecurityAuditEvent, SecurityAuditLog};
use crate::{CapabilityManifest, DCPError, SecurityError};

use super::json_rpc::{
    JsonRpcError, JsonRpcParseError, JsonRpcParser, JsonRpcRequest, JsonRpcResponse, RequestId,
    DEFAULT_MAX_JSONRPC_REQUEST_SIZE,
};
use super::request_replay::{replay_key, RequestReplayGuard};

/// Complete adapter errors
#[derive(Debug, Clone, thiserror::Error)]
pub enum CompleteAdapterError {
    #[error("JSON-RPC parse error: {0}")]
    ParseError(#[from] JsonRpcParseError),
    #[error("unknown tool: {0}")]
    UnknownTool(String),
    #[error("DCP error: {0}")]
    DcpError(#[from] DCPError),
    #[error("resource error: {0}")]
    ResourceError(String),
    #[error("prompt error: {0}")]
    PromptError(String),
    #[error("serialization error: {0}")]
    SerializationError(String),
    #[error("invalid params: {0}")]
    InvalidParams(String),
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("lifecycle not initialized")]
    LifecycleNotInitialized,
    #[error("lifecycle already initialized")]
    LifecycleAlreadyInitialized,
    #[error("capability denied")]
    CapabilityDenied,
    #[error("{kind} capacity exceeded")]
    CapacityExceeded { kind: &'static str, max: usize },
}

impl From<ResourceError> for CompleteAdapterError {
    fn from(e: ResourceError) -> Self {
        Self::ResourceError(e.to_string())
    }
}

/// Prompt template
#[derive(Debug, Clone)]
pub struct PromptTemplate {
    /// Unique name
    pub name: String,
    /// Description
    pub description: String,
    /// Arguments
    pub arguments: Vec<PromptArgument>,
    /// Template content with {{arg}} placeholders
    pub template: String,
}

/// Prompt argument
#[derive(Debug, Clone)]
pub struct PromptArgument {
    /// Argument name
    pub name: String,
    /// Description
    pub description: String,
    /// Whether required
    pub required: bool,
}

impl PromptTemplate {
    /// Create a new prompt template
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        template: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            arguments: Vec::new(),
            template: template.into(),
        }
    }

    /// Add an argument
    pub fn with_argument(
        mut self,
        name: impl Into<String>,
        description: impl Into<String>,
        required: bool,
    ) -> Self {
        self.arguments.push(PromptArgument {
            name: name.into(),
            description: description.into(),
            required,
        });
        self
    }

    /// Render the template with arguments
    pub fn render(&self, args: &HashMap<String, String>) -> Result<String, CompleteAdapterError> {
        for argument_name in args.keys() {
            if !self.arguments.iter().any(|arg| arg.name == *argument_name) {
                return Err(CompleteAdapterError::InvalidParams(
                    "unknown prompt argument".to_string(),
                ));
            }
        }

        // Check required arguments
        for arg in &self.arguments {
            if arg.required && !args.contains_key(&arg.name) {
                return Err(CompleteAdapterError::PromptError(format!(
                    "missing required argument: {}",
                    arg.name
                )));
            }
        }

        // Substitute placeholders
        let mut result = self.template.clone();
        for (key, value) in args {
            let placeholder = format!("{{{{{}}}}}", key);
            result = result.replace(&placeholder, value);
        }

        Ok(result)
    }

    fn has_argument(&self, name: &str) -> bool {
        self.arguments.iter().any(|arg| arg.name == name)
    }
}

/// Log level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogLevel {
    Debug,
    #[default]
    Info,
    Warning,
    Error,
}

impl LogLevel {
    fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "debug" => Some(Self::Debug),
            "info" => Some(Self::Info),
            "warning" | "warn" => Some(Self::Warning),
            "error" => Some(Self::Error),
            _ => None,
        }
    }
}

fn set_manifest_ids(
    value: Option<&Value>,
    field: &'static str,
    max_id_exclusive: usize,
    mut set: impl FnMut(u16),
) -> Result<(), CompleteAdapterError> {
    let Some(value) = value else {
        return Ok(());
    };
    let ids = value.as_array().ok_or_else(|| {
        CompleteAdapterError::InvalidParams("capability ids must be array".into())
    })?;

    for id in ids {
        let id = id.as_u64().ok_or_else(|| {
            CompleteAdapterError::InvalidParams("capability id must be integer".into())
        })?;
        if id >= max_id_exclusive as u64 {
            return Err(CompleteAdapterError::InvalidParams(format!(
                "{field} capability id out of range"
            )));
        }
        set(id as u16);
    }

    Ok(())
}

fn set_extension_ids(
    value: Option<&Value>,
    manifest: &mut CapabilityManifest,
) -> Result<(), CompleteAdapterError> {
    let Some(value) = value else {
        return Ok(());
    };
    let ids = value.as_array().ok_or_else(|| {
        CompleteAdapterError::InvalidParams("capability ids must be array".into())
    })?;

    for id in ids {
        let id = id.as_u64().ok_or_else(|| {
            CompleteAdapterError::InvalidParams("capability id must be integer".into())
        })?;
        if id >= 64 {
            return Err(CompleteAdapterError::InvalidParams(
                "extension capability id out of range".into(),
            ));
        }
        manifest.set_extension(id as u8);
    }

    Ok(())
}

fn optional_object<'a>(
    value: Option<&'a Value>,
    field: &'static str,
) -> Result<Option<&'a Map<String, Value>>, CompleteAdapterError> {
    match value {
        None => Ok(None),
        Some(Value::Object(object)) => Ok(Some(object)),
        Some(_) => Err(CompleteAdapterError::InvalidParams(format!(
            "{field} must be object"
        ))),
    }
}

fn tool_input_schema_json(schema: &InputSchema) -> Value {
    let mut properties = Map::new();
    let mut required = Vec::new();

    for (idx, field) in schema.fields.iter().take(16).enumerate() {
        let mut property = Map::new();
        property.insert(
            "type".to_string(),
            Value::String(
                match field.field_type {
                    ArgType::Null => "null",
                    ArgType::Bool => "boolean",
                    ArgType::I32 | ArgType::I64 => "integer",
                    ArgType::F64 => "number",
                    ArgType::String | ArgType::Bytes => "string",
                    ArgType::Array => "array",
                    ArgType::Object => "object",
                }
                .to_string(),
            ),
        );

        if matches!(field.field_type, ArgType::String | ArgType::Bytes) && field.size > 0 {
            property.insert(
                "maxLength".to_string(),
                Value::Number(serde_json::Number::from(field.size)),
            );
        }

        if let Some((minimum, maximum)) = field.enum_range {
            property.insert(
                "minimum".to_string(),
                Value::Number(serde_json::Number::from(minimum)),
            );
            property.insert(
                "maximum".to_string(),
                Value::Number(serde_json::Number::from(maximum)),
            );
        }

        if schema.is_required(idx) {
            required.push(Value::String(field.name.to_string()));
        }

        properties.insert(field.name.to_string(), Value::Object(property));
    }

    let mut root = Map::new();
    root.insert("type".to_string(), Value::String("object".to_string()));
    root.insert("properties".to_string(), Value::Object(properties));
    root.insert("additionalProperties".to_string(), Value::Bool(false));
    if !required.is_empty() {
        root.insert("required".to_string(), Value::Array(required));
    }

    Value::Object(root)
}

fn validate_field_capacity(field: &FieldDef, minimum: usize) -> Result<(), CompleteAdapterError> {
    if field.size as usize >= minimum {
        Ok(())
    } else {
        Err(CompleteAdapterError::DcpError(DCPError::ValidationFailed))
    }
}

fn write_field(
    buffer: &mut [u8],
    field: &FieldDef,
    bytes: &[u8],
) -> Result<(), CompleteAdapterError> {
    let offset = field.offset as usize;
    let end = offset
        .checked_add(bytes.len())
        .ok_or(CompleteAdapterError::DcpError(DCPError::OutOfBounds))?;
    if bytes.len() > field.size as usize || end > buffer.len() {
        return Err(CompleteAdapterError::DcpError(DCPError::OutOfBounds));
    }

    buffer[offset..end].copy_from_slice(bytes);
    Ok(())
}

fn encode_json_argument(
    buffer: &mut [u8],
    field: &FieldDef,
    value: &Value,
) -> Result<(), CompleteAdapterError> {
    match field.field_type {
        ArgType::Null => {
            if value.is_null() {
                Ok(())
            } else {
                Err(CompleteAdapterError::InvalidParams(
                    "argument type mismatch".to_string(),
                ))
            }
        }
        ArgType::Bool => {
            validate_field_capacity(field, 1)?;
            let value = value.as_bool().ok_or_else(|| {
                CompleteAdapterError::InvalidParams("argument type mismatch".to_string())
            })?;
            write_field(buffer, field, &[u8::from(value)])
        }
        ArgType::I32 => {
            if let Some((minimum, maximum)) = field.enum_range {
                validate_field_capacity(field, 1)?;
                let value = value.as_u64().ok_or_else(|| {
                    CompleteAdapterError::InvalidParams("argument type mismatch".to_string())
                })?;
                if value < minimum as u64 || value > maximum as u64 {
                    return Err(CompleteAdapterError::InvalidParams(
                        "argument out of range".to_string(),
                    ));
                }
                write_field(buffer, field, &[value as u8])
            } else {
                validate_field_capacity(field, 4)?;
                let value = value.as_i64().ok_or_else(|| {
                    CompleteAdapterError::InvalidParams("argument type mismatch".to_string())
                })?;
                let value = i32::try_from(value).map_err(|_| {
                    CompleteAdapterError::InvalidParams("argument out of range".to_string())
                })?;
                write_field(buffer, field, &value.to_le_bytes())
            }
        }
        ArgType::I64 => {
            validate_field_capacity(field, 8)?;
            let value = value.as_i64().ok_or_else(|| {
                CompleteAdapterError::InvalidParams("argument type mismatch".to_string())
            })?;
            write_field(buffer, field, &value.to_le_bytes())
        }
        ArgType::F64 => {
            validate_field_capacity(field, 8)?;
            let value = value.as_f64().ok_or_else(|| {
                CompleteAdapterError::InvalidParams("argument type mismatch".to_string())
            })?;
            write_field(buffer, field, &value.to_le_bytes())
        }
        ArgType::String | ArgType::Bytes => {
            let value = value.as_str().ok_or_else(|| {
                CompleteAdapterError::InvalidParams("argument type mismatch".to_string())
            })?;
            if value.len() > field.size as usize {
                return Err(CompleteAdapterError::InvalidParams(
                    "argument too large".to_string(),
                ));
            }
            write_field(buffer, field, value.as_bytes())
        }
        ArgType::Array => {
            if !value.is_array() {
                return Err(CompleteAdapterError::InvalidParams(
                    "argument type mismatch".to_string(),
                ));
            }
            let bytes = serde_json::to_vec(value)
                .map_err(|e| CompleteAdapterError::SerializationError(e.to_string()))?;
            if bytes.len() > field.size as usize {
                return Err(CompleteAdapterError::InvalidParams(
                    "argument too large".to_string(),
                ));
            }
            write_field(buffer, field, &bytes)
        }
        ArgType::Object => {
            if !value.is_object() {
                return Err(CompleteAdapterError::InvalidParams(
                    "argument type mismatch".to_string(),
                ));
            }
            let bytes = serde_json::to_vec(value)
                .map_err(|e| CompleteAdapterError::SerializationError(e.to_string()))?;
            if bytes.len() > field.size as usize {
                return Err(CompleteAdapterError::InvalidParams(
                    "argument too large".to_string(),
                ));
            }
            write_field(buffer, field, &bytes)
        }
    }
}

fn encode_json_arguments(
    schema: &InputSchema,
    arguments: Option<&Value>,
) -> Result<(Vec<u8>, u64), CompleteAdapterError> {
    let empty_arguments = Map::new();
    let arguments = match arguments {
        Some(Value::Object(arguments)) => arguments,
        Some(_) => {
            return Err(CompleteAdapterError::InvalidParams(
                "arguments must be object".to_string(),
            ));
        }
        None => &empty_arguments,
    };

    let max_len = schema
        .fields
        .iter()
        .try_fold(0usize, |max_len, field| {
            let end = (field.offset as usize)
                .checked_add(field.size as usize)
                .ok_or(DCPError::OutOfBounds)?;
            Ok::<usize, DCPError>(max_len.max(end))
        })
        .map_err(CompleteAdapterError::DcpError)?;
    let mut buffer = vec![0u8; max_len];
    let mut layout = 0u64;

    for argument_name in arguments.keys() {
        if !schema
            .fields
            .iter()
            .any(|field| field.name == argument_name.as_str())
        {
            return Err(CompleteAdapterError::InvalidParams(
                "unknown argument".to_string(),
            ));
        }
    }

    for (idx, field) in schema.fields.iter().enumerate() {
        if idx >= 16 {
            return Err(CompleteAdapterError::DcpError(DCPError::ValidationFailed));
        }

        match arguments.get(field.name) {
            Some(value) => {
                encode_json_argument(&mut buffer, field, value)?;
                let shift = idx * 4;
                layout |= (field.field_type as u64) << shift;
            }
            None if schema.is_required(idx) => {
                return Err(CompleteAdapterError::InvalidParams(
                    "missing required argument".to_string(),
                ));
            }
            None => {}
        }
    }

    Ok((buffer, layout))
}

fn tools_call_params_object(
    params: Option<&Value>,
) -> Result<&Map<String, Value>, CompleteAdapterError> {
    let Some(Value::Object(params)) = params else {
        return Err(CompleteAdapterError::InvalidParams(
            "tools/call params must be an object".into(),
        ));
    };

    if params
        .keys()
        .any(|key| key != "name" && key != "arguments" && key != "_meta")
    {
        return Err(CompleteAdapterError::InvalidParams(
            "tools/call params contain unsupported fields".into(),
        ));
    }

    if let Some(meta) = params.get("_meta") {
        if !meta.is_object() {
            return Err(CompleteAdapterError::InvalidParams(
                "tools/call _meta must be an object".into(),
            ));
        }
    }

    Ok(params)
}

/// Complete MCP adapter with full protocol support
pub struct CompleteMcpAdapter {
    /// Tool name to ID cache
    tool_cache: HashMap<String, u16>,
    /// ID to tool name reverse mapping
    id_to_name: HashMap<u16, String>,
    /// Resource registry
    resources: Arc<RwLock<ResourceRegistry>>,
    /// Prompt templates
    prompts: HashMap<String, PromptTemplate>,
    /// Current log level
    log_level: RwLock<LogLevel>,
    /// Server name
    server_name: String,
    /// Server version
    server_version: String,
    /// Negotiated protocol version
    protocol_version: RwLock<super::mcp2025::ProtocolVersion>,
    /// Version negotiator
    version_negotiator: super::mcp2025::VersionNegotiator,
    /// Roots registry
    roots: Arc<super::mcp2025::RootsRegistry>,
    /// Subscription tracker
    subscriptions: Arc<super::mcp2025::SubscriptionTracker>,
    /// Elicitation handler
    elicitation: Arc<super::mcp2025::ElicitationHandler>,
    /// Resource template registry
    resource_templates: Arc<super::mcp2025::ResourceTemplateRegistry>,
    /// Notification manager
    notifications: Arc<super::mcp2025::NotificationManager>,
    /// Cancellation manager
    cancellation: Arc<super::mcp2025::CancellationManager>,
    /// Progress tracker
    progress: Arc<super::mcp2025::ProgressTracker>,
    /// Prompt name to negotiated capability ID.
    prompt_ids: HashMap<String, u16>,
    /// Server-side capability offer.
    server_manifest: CapabilityManifest,
    /// Optional server-side authorization policy applied after registration.
    authorization_policy: Option<CapabilityManifest>,
    /// Negotiated capabilities for the current adapter session.
    negotiated_manifest: RwLock<CapabilityManifest>,
    /// Whether lifecycle initialization has already negotiated this session.
    initialize_seen: RwLock<bool>,
    /// Whether the client has completed the initialized lifecycle notification.
    initialized_seen: RwLock<bool>,
    /// Structured security audit receipts.
    security_audit: SecurityAuditLog,
    /// Bounded replay tracking for side-effecting tool calls in this adapter session.
    tool_call_replay_guard: RwLock<RequestReplayGuard>,
    /// Maximum accepted JSON-RPC request size in bytes.
    max_request_size: usize,
}

impl CompleteMcpAdapter {
    /// Create a new complete adapter
    pub fn new() -> Self {
        Self {
            tool_cache: HashMap::new(),
            id_to_name: HashMap::new(),
            resources: Arc::new(RwLock::new(ResourceRegistry::new())),
            prompts: HashMap::new(),
            log_level: RwLock::new(LogLevel::default()),
            server_name: "dcp-server".to_string(),
            server_version: env!("CARGO_PKG_VERSION").to_string(),
            protocol_version: RwLock::new(super::mcp2025::ProtocolVersion::default()),
            version_negotiator: super::mcp2025::VersionNegotiator::new(),
            roots: Arc::new(super::mcp2025::RootsRegistry::new()),
            subscriptions: Arc::new(super::mcp2025::SubscriptionTracker::new()),
            elicitation: Arc::new(super::mcp2025::ElicitationHandler::new()),
            resource_templates: Arc::new(super::mcp2025::ResourceTemplateRegistry::new()),
            notifications: Arc::new(super::mcp2025::NotificationManager::new()),
            cancellation: Arc::new(super::mcp2025::CancellationManager::new()),
            progress: Arc::new(super::mcp2025::ProgressTracker::new()),
            prompt_ids: HashMap::new(),
            server_manifest: CapabilityManifest::new(1),
            authorization_policy: None,
            negotiated_manifest: RwLock::new(CapabilityManifest::new(1)),
            initialize_seen: RwLock::new(false),
            initialized_seen: RwLock::new(false),
            security_audit: SecurityAuditLog::new(),
            tool_call_replay_guard: RwLock::new(RequestReplayGuard::default()),
            max_request_size: DEFAULT_MAX_JSONRPC_REQUEST_SIZE,
        }
    }

    /// Set server info
    pub fn with_server_info(mut self, name: impl Into<String>, version: impl Into<String>) -> Self {
        self.server_name = name.into();
        self.server_version = version.into();
        self
    }

    /// Set maximum JSON-RPC request size for adapter entry points.
    pub fn with_max_request_size(mut self, max_request_size: usize) -> Self {
        self.max_request_size = max_request_size;
        self
    }

    /// Restrict negotiation with an explicit server-side authorization policy.
    pub fn with_authorization_policy(mut self, authorization_policy: CapabilityManifest) -> Self {
        self.authorization_policy = Some(authorization_policy);
        self
    }

    /// Register a tool
    pub fn register_tool(
        &mut self,
        name: impl Into<String>,
        tool_id: u16,
    ) -> Result<u16, CompleteAdapterError> {
        let name = name.into();
        if (tool_id as usize) >= CapabilityManifest::MAX_TOOLS {
            self.audit_tool_registration_failure(
                "tool_registration_capacity_exceeded",
                tool_id,
                &name,
            );
            return Err(CompleteAdapterError::CapacityExceeded {
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
            return Err(CompleteAdapterError::InvalidRequest(
                "duplicate tool name".into(),
            ));
        }
        if self.id_to_name.contains_key(&tool_id) {
            self.audit_tool_registration_failure("tool_registration_duplicate_id", tool_id, &name);
            return Err(CompleteAdapterError::InvalidRequest(
                "duplicate tool id".into(),
            ));
        }

        self.tool_cache.insert(name.clone(), tool_id);
        self.id_to_name.insert(tool_id, name);
        self.server_manifest.set_tool(tool_id);
        Ok(tool_id)
    }

    /// Get resource registry for registration
    pub fn resources(&self) -> Arc<RwLock<ResourceRegistry>> {
        Arc::clone(&self.resources)
    }

    /// Register a prompt template
    pub fn register_prompt(
        &mut self,
        template: PromptTemplate,
    ) -> Result<u16, CompleteAdapterError> {
        if self.prompt_ids.contains_key(&template.name) {
            return Err(CompleteAdapterError::InvalidRequest(
                "duplicate prompt name".into(),
            ));
        }
        if self.prompts.len() >= CapabilityManifest::MAX_PROMPTS {
            return Err(CompleteAdapterError::CapacityExceeded {
                kind: "prompt",
                max: CapabilityManifest::MAX_PROMPTS,
            });
        }

        let prompt_id = self.prompts.len() as u16;
        self.prompt_ids.insert(template.name.clone(), prompt_id);
        self.prompts.insert(template.name.clone(), template);
        self.server_manifest.set_prompt(prompt_id);
        Ok(prompt_id)
    }

    /// Get structured security audit receipts.
    pub fn security_audit(&self) -> SecurityAuditLog {
        self.security_audit.clone()
    }

    fn audit_tool_registration_failure(&self, reason: &'static str, tool_id: u16, name: &str) {
        self.security_audit.record(
            SecurityAuditEvent::new(SecurityAuditAction::ValidationRejected, reason)
                .with_field("adapter", "complete_mcp")
                .with_field("operation", "tool_registration")
                .with_field("tool_id", tool_id.to_string())
                .with_field("tool_name", name),
        );
    }

    fn client_manifest_from_initialize(
        params: Option<&Value>,
    ) -> Result<CapabilityManifest, CompleteAdapterError> {
        let mut manifest = CapabilityManifest::new(1);
        let params = optional_object(params, "initialize params")?;
        let capabilities = if let Some(params) = params {
            let legacy_dcp_capabilities = params.get("dcpCapabilities");
            let standard_dcp_capabilities = if let Some(capabilities) = params.get("capabilities") {
                optional_object(Some(capabilities), "capabilities")?
                    .and_then(|capabilities| capabilities.get("dcp"))
            } else {
                None
            };
            if legacy_dcp_capabilities.is_some()
                && standard_dcp_capabilities.is_some()
                && legacy_dcp_capabilities != standard_dcp_capabilities
            {
                return Err(CompleteAdapterError::InvalidParams(
                    "conflicting dcp capabilities".into(),
                ));
            }
            standard_dcp_capabilities.or(legacy_dcp_capabilities)
        } else {
            None
        };
        let capabilities = optional_object(capabilities, "dcp capabilities")?;

        if let Some(capabilities) = capabilities {
            set_manifest_ids(
                capabilities.get("tools"),
                "tool",
                CapabilityManifest::MAX_TOOLS,
                |id| manifest.set_tool(id),
            )?;
            set_manifest_ids(
                capabilities.get("resources"),
                "resource",
                CapabilityManifest::MAX_RESOURCES,
                |id| manifest.set_resource(id),
            )?;
            set_manifest_ids(
                capabilities.get("prompts"),
                "prompt",
                CapabilityManifest::MAX_PROMPTS,
                |id| manifest.set_prompt(id),
            )?;
            set_extension_ids(capabilities.get("extensions"), &mut manifest)?;
        }

        Ok(manifest)
    }

    fn is_notification_only_method(method: &str) -> bool {
        matches!(
            method,
            "notifications/initialized" | "notifications/cancelled"
        )
    }

    fn is_server_to_client_request_method(method: &str) -> bool {
        matches!(
            method,
            "roots/list" | "elicitation/create" | "sampling/createMessage"
        )
    }

    fn is_remote_shutdown_method(method: &str) -> bool {
        matches!(
            method,
            "shutdown" | "exit" | "terminate" | "server/shutdown" | "notifications/shutdown"
        )
    }

    fn requires_initialized(method: &str) -> bool {
        matches!(
            method,
            "roots/list"
                | "elicitation/create"
                | "tools/list"
                | "tools/call"
                | "resources/list"
                | "resources/read"
                | "resources/subscribe"
                | "resources/unsubscribe"
                | "prompts/list"
                | "prompts/get"
                | "logging/setLevel"
                | "sampling/createMessage"
                | "completion/complete"
        )
    }

    async fn require_initialized_for_method(
        &self,
        request: &JsonRpcRequest,
    ) -> Result<(), CompleteAdapterError> {
        if !Self::requires_initialized(&request.method) || *self.initialized_seen.read().await {
            return Ok(());
        }

        Err(CompleteAdapterError::LifecycleNotInitialized)
    }

    fn require_request_method(
        &self,
        request: &JsonRpcRequest,
        expected_method: &'static str,
    ) -> Result<(), CompleteAdapterError> {
        if request.method == expected_method && !request.is_notification() {
            return Ok(());
        }

        self.audit_request(
            SecurityAuditAction::ValidationRejected,
            "invalid_request",
            request,
        );
        Err(CompleteAdapterError::InvalidRequest(format!(
            "{expected_method} requires a JSON-RPC request id"
        )))
    }

    fn require_notification_method(
        &self,
        request: &JsonRpcRequest,
        expected_method: &'static str,
    ) -> Result<(), CompleteAdapterError> {
        if request.method == expected_method && request.is_notification() {
            return Ok(());
        }

        self.audit_request(
            SecurityAuditAction::ValidationRejected,
            "invalid_request",
            request,
        );
        Err(CompleteAdapterError::InvalidRequest(format!(
            "{expected_method} requires a JSON-RPC notification"
        )))
    }

    fn list_cursor<'a>(
        &self,
        request: &'a JsonRpcRequest,
    ) -> Result<Option<&'a str>, CompleteAdapterError> {
        let Some(params) = optional_object(request.params.as_ref(), "list params")? else {
            return Ok(None);
        };

        for key in params.keys() {
            if key != "cursor" && key != "_meta" {
                return Err(CompleteAdapterError::InvalidParams(
                    "unsupported list param".into(),
                ));
            }
        }

        if let Some(meta) = params.get("_meta") {
            if !meta.is_object() {
                return Err(CompleteAdapterError::InvalidParams(
                    "list _meta must be object".into(),
                ));
            }
        }

        match params.get("cursor") {
            None => Ok(None),
            Some(Value::String(cursor)) => Ok(Some(cursor.as_str())),
            Some(_) => Err(CompleteAdapterError::InvalidParams(
                "list cursor must be string".into(),
            )),
        }
    }

    fn request_id_for_audit(id: &RequestId) -> Option<String> {
        match id {
            RequestId::String(s) => Some(s.clone()),
            RequestId::Number(n) => Some(n.to_string()),
            RequestId::Null => Some("null".to_string()),
            RequestId::Missing => None,
        }
    }

    fn audit_request(
        &self,
        action: SecurityAuditAction,
        reason: &'static str,
        request: &JsonRpcRequest,
    ) {
        let mut event = SecurityAuditEvent::new(action, reason).with_method(request.method.clone());
        if let Some(request_id) = Self::request_id_for_audit(&request.id) {
            event = event.with_request_id(request_id);
        }
        self.security_audit.record(event);
    }

    async fn record_tool_call_request_id(
        &self,
        request: &JsonRpcRequest,
    ) -> Result<bool, CompleteAdapterError> {
        let Some(request_id) = Self::request_id_for_audit(&request.id) else {
            return Ok(true);
        };

        let mut guard = self.tool_call_replay_guard.write().await;
        Ok(guard.check_and_record(replay_key("tools/call", &request_id)))
    }

    fn server_to_client_method_response(
        &self,
        request: &JsonRpcRequest,
    ) -> Result<String, CompleteAdapterError> {
        self.audit_request(
            SecurityAuditAction::RequestRejected,
            "server_to_client_method",
            request,
        );
        self.format_error(request.id.clone(), JsonRpcError::method_not_found())
    }

    fn adapter_error_response(
        &self,
        request: &JsonRpcRequest,
        error: CompleteAdapterError,
    ) -> Result<String, CompleteAdapterError> {
        let (action, reason, json_error) = match error {
            CompleteAdapterError::InvalidParams(_) => (
                SecurityAuditAction::ValidationRejected,
                "invalid_params",
                JsonRpcError::invalid_params(),
            ),
            CompleteAdapterError::ParseError(JsonRpcParseError::InvalidJson(_)) => (
                SecurityAuditAction::ValidationRejected,
                "parse_error",
                JsonRpcError::parse_error(),
            ),
            CompleteAdapterError::ParseError(JsonRpcParseError::RequestIdTooLarge) => (
                SecurityAuditAction::ValidationRejected,
                "request_id_too_large",
                JsonRpcError::invalid_request(),
            ),
            CompleteAdapterError::ParseError(JsonRpcParseError::RequestIdSensitive) => (
                SecurityAuditAction::ValidationRejected,
                "request_id_sensitive",
                JsonRpcError::invalid_request(),
            ),
            CompleteAdapterError::ParseError(JsonRpcParseError::BatchUnsupported) => (
                SecurityAuditAction::ValidationRejected,
                "batch_unsupported",
                JsonRpcError::invalid_request(),
            ),
            CompleteAdapterError::ParseError(_) => (
                SecurityAuditAction::ValidationRejected,
                "invalid_request",
                JsonRpcError::invalid_request(),
            ),
            CompleteAdapterError::InvalidRequest(_) => (
                SecurityAuditAction::ValidationRejected,
                "invalid_request",
                JsonRpcError::invalid_request(),
            ),
            CompleteAdapterError::LifecycleNotInitialized => (
                SecurityAuditAction::RequestRejected,
                "lifecycle_not_initialized",
                JsonRpcError::invalid_request(),
            ),
            CompleteAdapterError::LifecycleAlreadyInitialized => (
                SecurityAuditAction::RequestRejected,
                "lifecycle_already_initialized",
                JsonRpcError::invalid_request(),
            ),
            CompleteAdapterError::UnknownTool(_) => (
                SecurityAuditAction::CapabilityDenied,
                "unknown_tool",
                JsonRpcError::invalid_params(),
            ),
            CompleteAdapterError::CapabilityDenied => (
                SecurityAuditAction::CapabilityDenied,
                "capability_denied",
                JsonRpcError::new(-32001, "Capability denied"),
            ),
            CompleteAdapterError::CapacityExceeded { .. } => (
                SecurityAuditAction::ValidationRejected,
                "capacity_exceeded",
                JsonRpcError::invalid_request(),
            ),
            CompleteAdapterError::DcpError(_) => (
                SecurityAuditAction::RequestRejected,
                "dcp_error",
                JsonRpcError::new(-32000, "Request failed"),
            ),
            CompleteAdapterError::ResourceError(_) | CompleteAdapterError::PromptError(_) => (
                SecurityAuditAction::RequestRejected,
                "not_found",
                JsonRpcError::invalid_params(),
            ),
            CompleteAdapterError::SerializationError(_) => (
                SecurityAuditAction::RequestRejected,
                "serialization_error",
                JsonRpcError::internal_error(),
            ),
        };

        self.audit_request(action, reason, request);
        self.format_error(request.id.clone(), json_error)
    }

    async fn require_any_tool_capability(
        &self,
        _request: &JsonRpcRequest,
    ) -> Result<(), CompleteAdapterError> {
        if self.negotiated_manifest.read().await.tool_count() > 0 {
            Ok(())
        } else {
            Err(CompleteAdapterError::CapabilityDenied)
        }
    }

    async fn require_any_resource_capability(
        &self,
        _request: &JsonRpcRequest,
    ) -> Result<(), CompleteAdapterError> {
        if self.negotiated_manifest.read().await.resource_count() > 0 {
            Ok(())
        } else {
            Err(CompleteAdapterError::CapabilityDenied)
        }
    }

    async fn require_any_prompt_capability(
        &self,
        _request: &JsonRpcRequest,
    ) -> Result<(), CompleteAdapterError> {
        if self.negotiated_manifest.read().await.prompt_count() > 0 {
            Ok(())
        } else {
            Err(CompleteAdapterError::CapabilityDenied)
        }
    }

    async fn require_resource_uri_capability(&self, uri: &str) -> Result<(), CompleteAdapterError> {
        let resource_id = self
            .resources
            .read()
            .await
            .handler_id_for_uri(uri)
            .ok_or(CompleteAdapterError::CapabilityDenied)?;

        if self
            .negotiated_manifest
            .read()
            .await
            .has_resource(resource_id)
        {
            Ok(())
        } else {
            Err(CompleteAdapterError::CapabilityDenied)
        }
    }

    async fn require_tool_capability(&self, tool_id: u16) -> Result<(), CompleteAdapterError> {
        match self.negotiated_manifest.read().await.require_tool(tool_id) {
            Ok(()) => Ok(()),
            Err(SecurityError::InsufficientCapabilities) => {
                Err(CompleteAdapterError::CapabilityDenied)
            }
            Err(_) => Err(CompleteAdapterError::CapabilityDenied),
        }
    }

    /// Parse request
    pub fn parse_request(&self, json: &str) -> Result<JsonRpcRequest, CompleteAdapterError> {
        Ok(JsonRpcParser::parse_request_with_limit(
            json,
            self.max_request_size,
        )?)
    }

    /// Format success response
    pub fn format_success(
        &self,
        id: RequestId,
        result: Value,
    ) -> Result<String, CompleteAdapterError> {
        let response = JsonRpcResponse::success(id, result);
        JsonRpcParser::format_response(&response)
            .map_err(|e| CompleteAdapterError::SerializationError(e.to_string()))
    }

    /// Format error response
    pub fn format_error(
        &self,
        id: RequestId,
        error: JsonRpcError,
    ) -> Result<String, CompleteAdapterError> {
        let response = JsonRpcResponse::error(id, error);
        JsonRpcParser::format_response(&response)
            .map_err(|e| CompleteAdapterError::SerializationError(e.to_string()))
    }

    // ========================================================================
    // Lifecycle Methods
    // ========================================================================

    /// Handle initialize with protocol version negotiation
    pub async fn handle_initialize(
        &self,
        request: &JsonRpcRequest,
    ) -> Result<String, CompleteAdapterError> {
        self.require_request_method(request, "initialize")?;

        let client_manifest = Self::client_manifest_from_initialize(request.params.as_ref())?;
        let requested_version = match request
            .params
            .as_ref()
            .and_then(|p| p.get("protocolVersion"))
        {
            Some(Value::String(version)) => version.as_str(),
            Some(_) => {
                return Err(CompleteAdapterError::InvalidParams(
                    "protocolVersion must be string".into(),
                ));
            }
            None => "2024-11-05",
        };

        let negotiated = self
            .version_negotiator
            .try_negotiate(requested_version)
            .ok_or_else(|| {
                CompleteAdapterError::InvalidParams("unsupported protocolVersion".into())
            })?;

        {
            let mut initialize_seen = self.initialize_seen.write().await;
            if *initialize_seen {
                return Err(CompleteAdapterError::InvalidRequest(
                    "already initialized".to_string(),
                ));
            }
            *initialize_seen = true;
        }

        // Negotiate version
        *self.protocol_version.write().await = negotiated;

        let mut server_manifest = self.server_manifest.clone();
        for resource_id in self.resources.read().await.handler_ids() {
            server_manifest.set_resource(resource_id);
        }
        if let Some(authorization_policy) = self.authorization_policy.as_ref() {
            server_manifest = server_manifest.intersect(authorization_policy);
        }
        *self.negotiated_manifest.write().await =
            CapabilityManifest::negotiate(&client_manifest, &server_manifest);

        // Build capabilities from actual registered server boundaries.
        let negotiated_manifest = self.negotiated_manifest.read().await;
        let mut capabilities = serde_json::json!({
            "logging": {}
        });

        if negotiated_manifest.tool_count() > 0 {
            capabilities["tools"] = serde_json::json!({ "listChanged": true });
        }
        if negotiated_manifest.resource_count() > 0 {
            let supports_subscribe = self
                .resources
                .read()
                .await
                .any_allowed_supports_subscribe(|id| negotiated_manifest.has_resource(id));
            let mut resource_capabilities = Map::new();
            resource_capabilities.insert("listChanged".into(), Value::Bool(true));
            if supports_subscribe {
                resource_capabilities.insert("subscribe".into(), Value::Bool(true));
            }
            capabilities["resources"] = Value::Object(resource_capabilities);
        }
        if negotiated_manifest.prompt_count() > 0 {
            capabilities["prompts"] = serde_json::json!({ "listChanged": true });
        }
        drop(negotiated_manifest);

        let result = serde_json::json!({
            "protocolVersion": negotiated.as_str(),
            "capabilities": capabilities,
            "serverInfo": {
                "name": self.server_name,
                "version": self.server_version
            }
        });
        self.format_success(request.id.clone(), result)
    }

    /// Get the negotiated protocol version
    pub async fn protocol_version(&self) -> super::mcp2025::ProtocolVersion {
        *self.protocol_version.read().await
    }

    /// Handle initialized notification
    pub async fn handle_initialized(
        &self,
        request: &JsonRpcRequest,
    ) -> Result<Option<String>, CompleteAdapterError> {
        if request.method != "notifications/initialized" || !request.is_notification() {
            self.audit_request(
                SecurityAuditAction::ValidationRejected,
                "invalid_request",
                request,
            );
            return Err(CompleteAdapterError::InvalidRequest(
                "initialized must be a notifications/initialized notification".to_string(),
            ));
        }

        if request.params.is_some() {
            return Err(CompleteAdapterError::InvalidParams(
                "initialized notification must not include params".to_string(),
            ));
        }

        if !*self.initialize_seen.read().await {
            return Err(CompleteAdapterError::LifecycleNotInitialized);
        }

        let mut initialized_seen = self.initialized_seen.write().await;
        if *initialized_seen {
            return Err(CompleteAdapterError::LifecycleAlreadyInitialized);
        }
        *initialized_seen = true;

        // Notification - no response
        Ok(None)
    }

    // ========================================================================
    // Roots Methods (MCP 2025-03-26+)
    // ========================================================================

    /// Get the roots registry for configuration
    pub fn roots(&self) -> Arc<super::mcp2025::RootsRegistry> {
        Arc::clone(&self.roots)
    }

    /// Handle roots/list
    pub async fn handle_roots_list(
        &self,
        request: &JsonRpcRequest,
    ) -> Result<String, CompleteAdapterError> {
        self.require_request_method(request, "roots/list")?;
        self.require_initialized_for_method(request).await?;
        self.server_to_client_method_response(request)
    }

    // ========================================================================
    // Elicitation Methods (MCP 2025-06-18+)
    // ========================================================================

    /// Get the elicitation handler for configuration
    pub fn elicitation(&self) -> Arc<super::mcp2025::ElicitationHandler> {
        Arc::clone(&self.elicitation)
    }

    /// Handle elicitation/create
    pub async fn handle_elicitation_create(
        &self,
        request: &JsonRpcRequest,
    ) -> Result<String, CompleteAdapterError> {
        self.require_request_method(request, "elicitation/create")?;
        self.require_initialized_for_method(request).await?;
        self.server_to_client_method_response(request)
    }

    // ========================================================================
    // Resource Template Methods (MCP 2025-03-26+)
    // ========================================================================

    /// Get the resource template registry for configuration
    pub fn resource_templates(&self) -> Arc<super::mcp2025::ResourceTemplateRegistry> {
        Arc::clone(&self.resource_templates)
    }

    /// Get the notification manager
    pub fn notifications(&self) -> Arc<super::mcp2025::NotificationManager> {
        Arc::clone(&self.notifications)
    }

    /// Get the cancellation manager
    pub fn cancellation(&self) -> Arc<super::mcp2025::CancellationManager> {
        Arc::clone(&self.cancellation)
    }

    /// Get the progress tracker
    pub fn progress(&self) -> Arc<super::mcp2025::ProgressTracker> {
        Arc::clone(&self.progress)
    }

    // ========================================================================
    // Cancellation Methods
    // ========================================================================

    /// Handle notifications/cancelled
    pub async fn handle_cancelled(
        &self,
        request: &JsonRpcRequest,
    ) -> Result<Option<String>, CompleteAdapterError> {
        self.require_notification_method(request, "notifications/cancelled")?;

        let params = request
            .params
            .as_ref()
            .and_then(Value::as_object)
            .ok_or(CompleteAdapterError::InvalidParams("missing params".into()))?;

        if params
            .keys()
            .any(|key| key != "requestId" && key != "reason")
        {
            return Err(CompleteAdapterError::InvalidParams(
                "unsupported cancelled param".into(),
            ));
        }

        let request_id = params
            .get("requestId")
            .ok_or(CompleteAdapterError::InvalidParams(
                "missing requestId".into(),
            ))?;

        let request_id = match RequestId::try_from_json_value(request_id) {
            Ok(id @ (RequestId::Number(_) | RequestId::String(_))) => id,
            Ok(_) | Err(JsonRpcParseError::InvalidStructure) => {
                return Err(CompleteAdapterError::InvalidParams(
                    "invalid requestId".into(),
                ));
            }
            Err(JsonRpcParseError::RequestIdTooLarge) => {
                return Err(CompleteAdapterError::ParseError(
                    JsonRpcParseError::RequestIdTooLarge,
                ));
            }
            Err(JsonRpcParseError::RequestIdSensitive) => {
                return Err(CompleteAdapterError::ParseError(
                    JsonRpcParseError::RequestIdSensitive,
                ));
            }
            Err(_) => {
                return Err(CompleteAdapterError::InvalidParams(
                    "invalid requestId".into(),
                ));
            }
        };

        let reason = match params.get("reason") {
            None => None,
            Some(Value::String(reason)) => Some(sanitize_text(reason)),
            Some(_) => {
                return Err(CompleteAdapterError::InvalidParams(
                    "invalid cancellation reason".into(),
                ));
            }
        };

        // Cancel the request - this is idempotent
        self.cancellation.cancel(&request_id, reason).await;

        // Notifications don't return a response
        Ok(None)
    }

    // ========================================================================
    // Progress Methods
    // ========================================================================

    /// Extract progressToken from request _meta
    pub fn extract_progress_token(request: &JsonRpcRequest) -> Option<String> {
        request
            .params
            .as_ref()
            .and_then(|p| p.get("_meta"))
            .and_then(|m| m.get("progressToken"))
            .and_then(|t| t.as_str())
            .map(|s| s.to_string())
    }

    // ========================================================================
    // Ping/Pong Methods
    // ========================================================================

    /// Handle ping method
    pub fn handle_ping(&self, request: &JsonRpcRequest) -> Result<String, CompleteAdapterError> {
        self.require_request_method(request, "ping")?;
        // Return empty result object
        self.format_success(request.id.clone(), serde_json::json!({}))
    }

    // ========================================================================
    // Tool Methods
    // ========================================================================

    /// Handle tools/list
    pub async fn handle_tools_list(
        &self,
        request: &JsonRpcRequest,
        router: &BinaryTrieRouter,
    ) -> Result<String, CompleteAdapterError> {
        self.require_request_method(request, "tools/list")?;
        self.require_initialized_for_method(request).await?;
        let _ = self.list_cursor(request)?;
        self.require_any_tool_capability(request).await?;

        let negotiated = self.negotiated_manifest.read().await;
        let tools: Vec<Value> = self
            .tool_cache
            .iter()
            .filter_map(|(name, tool_id)| {
                if !negotiated.has_tool(*tool_id) {
                    return None;
                }

                let (description, input_schema) = router
                    .tool_schema(*tool_id)
                    .map(|schema| {
                        (
                            schema.description.to_string(),
                            tool_input_schema_json(&schema.input),
                        )
                    })
                    .unwrap_or_else(|| {
                        (
                            format!("Tool: {}", name),
                            serde_json::json!({
                                "type": "object",
                                "properties": {},
                                "additionalProperties": false
                            }),
                        )
                    });

                Some(serde_json::json!({
                    "name": name,
                    "description": description,
                    "inputSchema": input_schema
                }))
            })
            .collect();

        self.format_success(request.id.clone(), serde_json::json!({ "tools": tools }))
    }

    /// Handle tools/call
    pub async fn handle_tools_call(
        &self,
        request: &JsonRpcRequest,
        router: &BinaryTrieRouter,
    ) -> Result<String, CompleteAdapterError> {
        self.require_request_method(request, "tools/call")?;
        self.require_initialized_for_method(request).await?;

        let params = tools_call_params_object(request.params.as_ref())?;

        let tool_name = params.get("name").and_then(|v| v.as_str()).ok_or(
            CompleteAdapterError::InvalidParams("missing tool name".into()),
        )?;

        let tool_id = self
            .tool_cache
            .get(tool_name)
            .ok_or(CompleteAdapterError::CapabilityDenied)?;

        self.require_tool_capability(*tool_id).await?;

        let schema = router
            .tool_schema(*tool_id)
            .ok_or(CompleteAdapterError::DcpError(DCPError::ToolNotFound))?;
        let (args_bytes, arg_layout) =
            encode_json_arguments(&schema.input, params.get("arguments"))?;
        if !self.record_tool_call_request_id(request).await? {
            self.audit_request(
                SecurityAuditAction::ReplayRejected,
                "request_replay",
                request,
            );
            return self.format_error(
                request.id.clone(),
                JsonRpcError::new(-32002, "Request replay rejected"),
            );
        }

        let shared_args = SharedArgs::new(&args_bytes, arg_layout);
        let capabilities = self.negotiated_manifest.read().await.clone();
        let result = router
            .execute_authorized(&capabilities, *tool_id, &shared_args)
            .map_err(|error| match error {
                SecurityError::ValidationFailed => {
                    CompleteAdapterError::InvalidParams("argument validation failed".into())
                }
                SecurityError::InsufficientCapabilities => CompleteAdapterError::CapabilityDenied,
                _ => CompleteAdapterError::CapabilityDenied,
            })?;
        let result_value = match result {
            ToolResult::Success(data) => serde_json::from_slice(&data)
                .unwrap_or(Value::String(String::from_utf8_lossy(&data).into())),
            ToolResult::Empty => Value::Null,
            ToolResult::Error(e) => serde_json::json!({"error": e.to_string()}),
        };

        self.format_success(request.id.clone(), serde_json::json!({
            "content": [{ "type": "text", "text": serde_json::to_string(&result_value).unwrap_or_default() }]
        }))
    }

    // ========================================================================
    // Resource Methods
    // ========================================================================

    /// Handle resources/list
    pub async fn handle_resources_list(
        &self,
        request: &JsonRpcRequest,
    ) -> Result<String, CompleteAdapterError> {
        self.require_request_method(request, "resources/list")?;
        self.require_initialized_for_method(request).await?;
        let cursor = self.list_cursor(request)?;
        self.require_any_resource_capability(request).await?;

        let negotiated = self.negotiated_manifest.read().await;
        let registry = self.resources.read().await;
        let list =
            registry.list_allowed(cursor, |resource_id| negotiated.has_resource(resource_id))?;
        let allowed_templates: HashSet<String> = registry
            .allowed_uri_templates(|resource_id| negotiated.has_resource(resource_id))
            .into_iter()
            .collect();
        drop(registry);
        drop(negotiated);

        let mut resources = Vec::new();
        for resource in list.resources {
            if !self.roots.allows_uri(&resource.uri).await {
                continue;
            }

            resources.push(serde_json::json!({
                "uri": resource.uri,
                "name": resource.name,
                "description": resource.description,
                "mimeType": resource.mime_type
            }));
        }

        let mut result = serde_json::json!({ "resources": resources });
        if let Some(cursor) = list.next_cursor {
            result["nextCursor"] = Value::String(cursor);
        }

        // Include resource templates (MCP 2025-03-26+)
        let version = *self.protocol_version.read().await;
        if version.supports_roots() {
            let templates: Vec<_> = self
                .resource_templates
                .list()
                .await
                .into_iter()
                .filter(|template| allowed_templates.contains(&template.uri_template))
                .collect();
            if !templates.is_empty() {
                result["resourceTemplates"] =
                    serde_json::to_value(&templates).unwrap_or(Value::Array(vec![]));
            }
        }

        self.format_success(request.id.clone(), result)
    }

    /// Handle resources/read
    pub async fn handle_resources_read(
        &self,
        request: &JsonRpcRequest,
    ) -> Result<String, CompleteAdapterError> {
        self.require_request_method(request, "resources/read")?;
        self.require_initialized_for_method(request).await?;

        let uri = request
            .params
            .as_ref()
            .and_then(|p| p.get("uri"))
            .and_then(|v| v.as_str())
            .ok_or(CompleteAdapterError::InvalidParams("missing uri".into()))?;

        self.require_resource_uri_capability(uri).await?;

        if !self.roots.allows_uri(uri).await {
            return Err(CompleteAdapterError::InvalidParams(
                "resource outside configured roots".into(),
            ));
        }

        let registry = self.resources.read().await;
        let content = registry.read(uri)?;

        let content_value = match content {
            ResourceContent::Text {
                uri,
                mime_type,
                text,
            } => serde_json::json!({
                "uri": uri,
                "mimeType": mime_type,
                "text": text
            }),
            ResourceContent::Blob {
                uri,
                mime_type,
                blob,
            } => serde_json::json!({
                "uri": uri,
                "mimeType": mime_type,
                "blob": blob
            }),
        };

        self.format_success(
            request.id.clone(),
            serde_json::json!({
                "contents": [content_value]
            }),
        )
    }

    /// Handle resources/subscribe
    pub async fn handle_resources_subscribe(
        &self,
        request: &JsonRpcRequest,
    ) -> Result<String, CompleteAdapterError> {
        self.require_request_method(request, "resources/subscribe")?;
        self.require_initialized_for_method(request).await?;

        let uri = request
            .params
            .as_ref()
            .and_then(|p| p.get("uri"))
            .and_then(|v| v.as_str())
            .ok_or(CompleteAdapterError::InvalidParams("missing uri".into()))?;

        self.require_resource_uri_capability(uri).await?;

        if !self.roots.allows_uri(uri).await {
            return Err(CompleteAdapterError::InvalidParams(
                "resource outside configured roots".into(),
            ));
        }

        self.resources
            .read()
            .await
            .ensure_subscribable(uri)
            .map_err(CompleteAdapterError::from)?;

        // Track subscription (using a default client ID for now)
        if !self.subscriptions.subscribe(uri, "default").await {
            return Err(CompleteAdapterError::CapacityExceeded {
                kind: "subscription",
                max: super::mcp2025::SubscriptionTracker::DEFAULT_MAX_SUBSCRIBERS_PER_RESOURCE,
            });
        }

        self.format_success(request.id.clone(), serde_json::json!({}))
    }

    /// Handle resources/unsubscribe (idempotent)
    pub async fn handle_resources_unsubscribe(
        &self,
        request: &JsonRpcRequest,
    ) -> Result<String, CompleteAdapterError> {
        self.require_request_method(request, "resources/unsubscribe")?;
        self.require_initialized_for_method(request).await?;

        let uri = request
            .params
            .as_ref()
            .and_then(|p| p.get("uri"))
            .and_then(|v| v.as_str())
            .ok_or(CompleteAdapterError::InvalidParams("missing uri".into()))?;

        self.require_resource_uri_capability(uri).await?;

        if !self.roots.allows_uri(uri).await {
            return Err(CompleteAdapterError::InvalidParams(
                "resource outside configured roots".into(),
            ));
        }

        // Unsubscribe is idempotent - always succeeds
        self.subscriptions.unsubscribe(uri, "default").await;

        self.format_success(request.id.clone(), serde_json::json!({}))
    }

    // ========================================================================
    // Prompt Methods
    // ========================================================================

    /// Handle prompts/list
    pub async fn handle_prompts_list(
        &self,
        request: &JsonRpcRequest,
    ) -> Result<String, CompleteAdapterError> {
        self.require_request_method(request, "prompts/list")?;
        self.require_initialized_for_method(request).await?;
        let _ = self.list_cursor(request)?;
        self.require_any_prompt_capability(request).await?;

        let negotiated = self.negotiated_manifest.read().await;
        let prompts: Vec<Value> = self
            .prompts
            .iter()
            .filter(|(name, _)| {
                self.prompt_ids
                    .get(*name)
                    .map(|prompt_id| negotiated.has_prompt(*prompt_id))
                    .unwrap_or(false)
            })
            .map(|(_, p)| {
                let args: Vec<Value> = p
                    .arguments
                    .iter()
                    .map(|a| {
                        serde_json::json!({
                            "name": a.name,
                            "description": a.description,
                            "required": a.required
                        })
                    })
                    .collect();
                serde_json::json!({
                    "name": p.name,
                    "description": p.description,
                    "arguments": args
                })
            })
            .collect();

        self.format_success(
            request.id.clone(),
            serde_json::json!({ "prompts": prompts }),
        )
    }

    /// Handle prompts/get
    pub async fn handle_prompts_get(
        &self,
        request: &JsonRpcRequest,
    ) -> Result<String, CompleteAdapterError> {
        self.require_request_method(request, "prompts/get")?;
        self.require_initialized_for_method(request).await?;

        let params = request
            .params
            .as_ref()
            .ok_or(CompleteAdapterError::InvalidParams("missing params".into()))?;

        let name = params.get("name").and_then(|v| v.as_str()).ok_or(
            CompleteAdapterError::InvalidParams("missing prompt name".into()),
        )?;

        let prompt_id = self
            .prompt_ids
            .get(name)
            .copied()
            .ok_or(CompleteAdapterError::CapabilityDenied)?;
        if !self.negotiated_manifest.read().await.has_prompt(prompt_id) {
            return Err(CompleteAdapterError::CapabilityDenied);
        }

        let template = self
            .prompts
            .get(name)
            .ok_or_else(|| CompleteAdapterError::PromptError("prompt not found".to_string()))?;

        let args = if let Some(arguments) = params.get("arguments") {
            let arguments = arguments.as_object().ok_or_else(|| {
                CompleteAdapterError::InvalidParams("invalid prompt arguments".into())
            })?;
            let mut args = HashMap::new();
            for (key, value) in arguments {
                if !template.has_argument(key) {
                    return Err(CompleteAdapterError::InvalidParams(
                        "unknown prompt argument".into(),
                    ));
                }
                let value = value.as_str().ok_or_else(|| {
                    CompleteAdapterError::InvalidParams("invalid prompt argument".into())
                })?;
                args.insert(key.clone(), value.to_string());
            }
            args
        } else {
            HashMap::new()
        };

        let rendered = template.render(&args)?;

        self.format_success(
            request.id.clone(),
            serde_json::json!({
                "description": template.description,
                "messages": [{
                    "role": "user",
                    "content": { "type": "text", "text": rendered }
                }]
            }),
        )
    }

    // ========================================================================
    // Logging Methods
    // ========================================================================

    /// Handle logging/setLevel
    pub async fn handle_logging_set_level(
        &self,
        request: &JsonRpcRequest,
    ) -> Result<String, CompleteAdapterError> {
        self.require_request_method(request, "logging/setLevel")?;
        self.require_initialized_for_method(request).await?;

        let level_str = request
            .params
            .as_ref()
            .and_then(|p| p.get("level"))
            .and_then(|v| v.as_str())
            .ok_or(CompleteAdapterError::InvalidParams("missing level".into()))?;

        let level = LogLevel::from_str(level_str)
            .ok_or_else(|| CompleteAdapterError::InvalidParams("invalid log level".to_string()))?;

        *self.log_level.write().await = level;

        self.format_success(request.id.clone(), serde_json::json!({}))
    }

    // ========================================================================
    // Sampling Methods
    // ========================================================================

    /// Handle sampling/createMessage
    pub async fn handle_sampling_create_message(
        &self,
        request: &JsonRpcRequest,
    ) -> Result<String, CompleteAdapterError> {
        self.require_request_method(request, "sampling/createMessage")?;
        self.require_initialized_for_method(request).await?;
        self.server_to_client_method_response(request)
    }

    // ========================================================================
    // Completion Methods
    // ========================================================================

    /// Handle completion/complete
    pub async fn handle_completion_complete(
        &self,
        request: &JsonRpcRequest,
    ) -> Result<String, CompleteAdapterError> {
        self.require_request_method(request, "completion/complete")?;
        self.require_initialized_for_method(request).await?;

        let params = request
            .params
            .as_ref()
            .and_then(Value::as_object)
            .ok_or_else(|| CompleteAdapterError::InvalidParams("missing params".into()))?;

        let reference = params
            .get("ref")
            .and_then(Value::as_object)
            .ok_or_else(|| CompleteAdapterError::InvalidParams("invalid ref".into()))?;
        let ref_type = reference
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| CompleteAdapterError::InvalidParams("invalid ref".into()))?;

        let argument = params
            .get("argument")
            .and_then(Value::as_object)
            .ok_or_else(|| CompleteAdapterError::InvalidParams("invalid argument".into()))?;
        let argument_name = argument
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| CompleteAdapterError::InvalidParams("invalid argument".into()))?;
        let argument_value = argument
            .get("value")
            .and_then(Value::as_str)
            .ok_or_else(|| CompleteAdapterError::InvalidParams("invalid argument".into()))?;
        if argument_name.is_empty() || argument_value.is_empty() {
            return Err(CompleteAdapterError::InvalidParams(
                "invalid argument".into(),
            ));
        }

        match ref_type {
            "ref/prompt" => {
                let name = reference
                    .get("name")
                    .and_then(Value::as_str)
                    .ok_or_else(|| CompleteAdapterError::InvalidParams("invalid ref".into()))?;
                if name.is_empty() {
                    return Err(CompleteAdapterError::InvalidParams("invalid ref".into()));
                }
                let prompt_id = self
                    .prompt_ids
                    .get(name)
                    .copied()
                    .ok_or(CompleteAdapterError::CapabilityDenied)?;
                if !self.negotiated_manifest.read().await.has_prompt(prompt_id) {
                    return Err(CompleteAdapterError::CapabilityDenied);
                }
                let template = self.prompts.get(name).ok_or_else(|| {
                    CompleteAdapterError::PromptError("prompt not found".to_string())
                })?;
                let argument_name = params
                    .get("argument")
                    .and_then(Value::as_object)
                    .and_then(|argument| argument.get("name"))
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        CompleteAdapterError::InvalidParams("invalid argument".into())
                    })?;
                if !template.has_argument(argument_name) {
                    return Err(CompleteAdapterError::InvalidParams(
                        "unknown prompt argument".into(),
                    ));
                }
            }
            "ref/resource" => {
                let uri = reference
                    .get("uri")
                    .and_then(Value::as_str)
                    .ok_or_else(|| CompleteAdapterError::InvalidParams("invalid ref".into()))?;
                if uri.is_empty() {
                    return Err(CompleteAdapterError::InvalidParams("invalid ref".into()));
                }
                self.require_resource_uri_capability(uri).await?;
                if !self.roots.allows_uri(uri).await {
                    return Err(CompleteAdapterError::InvalidParams(
                        "resource outside configured roots".into(),
                    ));
                }
            }
            _ => return Err(CompleteAdapterError::InvalidParams("invalid ref".into())),
        }

        // Auto-completion stub
        self.format_success(
            request.id.clone(),
            serde_json::json!({
                "completion": { "values": [], "hasMore": false }
            }),
        )
    }

    // ========================================================================
    // Main Dispatch
    // ========================================================================

    /// Handle any MCP request
    pub async fn handle_request(
        &self,
        json: &str,
        router: &BinaryTrieRouter,
    ) -> Result<Option<String>, CompleteAdapterError> {
        let request = match self.parse_request(json) {
            Ok(request) => request,
            Err(error) => {
                let (reason, json_error) = match error {
                    CompleteAdapterError::ParseError(JsonRpcParseError::InvalidJson(_)) => {
                        ("parse_error", JsonRpcError::parse_error())
                    }
                    CompleteAdapterError::ParseError(JsonRpcParseError::RequestTooLarge) => {
                        ("request_too_large", JsonRpcError::invalid_request())
                    }
                    CompleteAdapterError::ParseError(JsonRpcParseError::RequestIdTooLarge) => {
                        ("request_id_too_large", JsonRpcError::invalid_request())
                    }
                    CompleteAdapterError::ParseError(JsonRpcParseError::RequestIdSensitive) => {
                        ("request_id_sensitive", JsonRpcError::invalid_request())
                    }
                    CompleteAdapterError::ParseError(JsonRpcParseError::BatchUnsupported) => {
                        ("batch_unsupported", JsonRpcError::invalid_request())
                    }
                    _ => ("invalid_request", JsonRpcError::invalid_request()),
                };
                self.security_audit.record(SecurityAuditEvent::new(
                    SecurityAuditAction::ValidationRejected,
                    reason,
                ));
                return self
                    .format_error(RequestId::Null, json_error)
                    .map(Some);
            }
        };

        // Check if notification (no id)
        let is_notification = request.is_notification();

        if Self::is_remote_shutdown_method(&request.method) {
            self.audit_request(
                SecurityAuditAction::ShutdownRejected,
                "remote_shutdown_rejected",
                &request,
            );

            if is_notification {
                return Ok(None);
            }

            return self
                .format_error(request.id.clone(), JsonRpcError::method_not_found())
                .map(Some);
        }

        if is_notification && !Self::is_notification_only_method(&request.method) {
            self.audit_request(
                SecurityAuditAction::RequestRejected,
                "notification_not_allowed",
                &request,
            );
            return Ok(None);
        }

        if !is_notification && Self::is_notification_only_method(&request.method) {
            self.audit_request(
                SecurityAuditAction::ValidationRejected,
                "notification_method_with_id",
                &request,
            );
            return self
                .format_error(request.id.clone(), JsonRpcError::invalid_request())
                .map(Some);
        }

        if !is_notification {
            if let Err(error) = self.require_initialized_for_method(&request).await {
                return self.adapter_error_response(&request, error).map(Some);
            }
        }

        let result = match request.method.as_str() {
            // Lifecycle
            "initialize" => self.handle_initialize(&request).await.map(Some),
            "notifications/initialized" => self.handle_initialized(&request).await,

            // Ping/Pong
            "ping" => self.handle_ping(&request).map(Some),

            // Server-to-client methods are not valid on this inbound request path.
            method if Self::is_server_to_client_request_method(method) => {
                self.server_to_client_method_response(&request).map(Some)
            }

            // Tools
            "tools/list" => match self.require_any_tool_capability(&request).await {
                Ok(()) => self.handle_tools_list(&request, router).await.map(Some),
                Err(error) => Err(error),
            },
            "tools/call" => self.handle_tools_call(&request, router).await.map(Some),

            // Resources
            "resources/list" => match self.require_any_resource_capability(&request).await {
                Ok(()) => self.handle_resources_list(&request).await.map(Some),
                Err(error) => Err(error),
            },
            "resources/read" => match self.require_any_resource_capability(&request).await {
                Ok(()) => self.handle_resources_read(&request).await.map(Some),
                Err(error) => Err(error),
            },
            "resources/subscribe" => match self.require_any_resource_capability(&request).await {
                Ok(()) => self.handle_resources_subscribe(&request).await.map(Some),
                Err(error) => Err(error),
            },
            "resources/unsubscribe" => match self.require_any_resource_capability(&request).await {
                Ok(()) => self.handle_resources_unsubscribe(&request).await.map(Some),
                Err(error) => Err(error),
            },

            // Prompts
            "prompts/list" => match self.require_any_prompt_capability(&request).await {
                Ok(()) => self.handle_prompts_list(&request).await.map(Some),
                Err(error) => Err(error),
            },
            "prompts/get" => match self.require_any_prompt_capability(&request).await {
                Ok(()) => self.handle_prompts_get(&request).await.map(Some),
                Err(error) => Err(error),
            },

            // Logging
            "logging/setLevel" => self.handle_logging_set_level(&request).await.map(Some),

            // Completion
            "completion/complete" => self.handle_completion_complete(&request).await.map(Some),

            // Notifications (no response)
            "notifications/cancelled" => self.handle_cancelled(&request).await,

            // Unknown method
            _ => {
                self.audit_request(
                    SecurityAuditAction::RequestRejected,
                    "method_not_found",
                    &request,
                );
                self.format_error(request.id.clone(), JsonRpcError::method_not_found())
                    .map(Some)
            }
        };

        // Don't return response for notifications
        if is_notification {
            if let Err(error) = result {
                let _ = self.adapter_error_response(&request, error);
            }
            Ok(None)
        } else if let Err(error) = result {
            self.adapter_error_response(&request, error)
                .map(Some)
        } else {
            result
        }
    }
}

impl Default for CompleteMcpAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prompt_template_render() {
        let template = PromptTemplate::new("test", "Test prompt", "Hello {{name}}!")
            .with_argument("name", "The name", true);

        let mut args = HashMap::new();
        args.insert("name".to_string(), "World".to_string());

        let rendered = template.render(&args).unwrap();
        assert_eq!(rendered, "Hello World!");
    }

    #[test]
    fn test_prompt_template_missing_required() {
        let template = PromptTemplate::new("test", "Test prompt", "Hello {{name}}!")
            .with_argument("name", "The name", true);

        let args = HashMap::new();
        let result = template.render(&args);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_complete_adapter_initialize() {
        let adapter = CompleteMcpAdapter::new();

        // When no version is specified, should default to 2024-11-05 for backward compatibility
        let request = JsonRpcRequest::new("initialize", None, RequestId::Number(1));
        let response = adapter.handle_initialize(&request).await.unwrap();
        let parsed = JsonRpcParser::parse_response(&response).unwrap();

        assert!(parsed.is_success());
        let result = parsed.result.unwrap();
        // When no version specified, defaults to 2024-11-05 for backward compatibility
        assert_eq!(result["protocolVersion"], "2024-11-05");
        // Should NOT have roots or elicitation capabilities (2024-11-05)
        assert!(result["capabilities"]["roots"].is_null());
        assert!(result["capabilities"]["elicitation"].is_null());
    }

    #[tokio::test]
    async fn test_complete_adapter_initialize_version_negotiation() {
        // Test with 2024-11-05
        let adapter = CompleteMcpAdapter::new();
        let request = JsonRpcRequest::new(
            "initialize",
            Some(serde_json::json!({"protocolVersion": "2024-11-05"})),
            RequestId::Number(1),
        );
        let response = adapter.handle_initialize(&request).await.unwrap();
        let parsed = JsonRpcParser::parse_response(&response).unwrap();
        let result = parsed.result.unwrap();
        assert_eq!(result["protocolVersion"], "2024-11-05");
        // Should not have roots capability
        assert!(result["capabilities"]["roots"].is_null());

        // Test with 2025-03-26
        let adapter = CompleteMcpAdapter::new();
        let request = JsonRpcRequest::new(
            "initialize",
            Some(serde_json::json!({"protocolVersion": "2025-03-26"})),
            RequestId::Number(2),
        );
        let response = adapter.handle_initialize(&request).await.unwrap();
        let parsed = JsonRpcParser::parse_response(&response).unwrap();
        let result = parsed.result.unwrap();
        assert_eq!(result["protocolVersion"], "2025-03-26");
        // Client-side capabilities are not advertised as server capabilities.
        assert!(result["capabilities"]["roots"].is_null());
        assert!(result["capabilities"]["elicitation"].is_null());

        // Test with 2025-06-18
        let adapter = CompleteMcpAdapter::new();
        let request = JsonRpcRequest::new(
            "initialize",
            Some(serde_json::json!({"protocolVersion": "2025-06-18"})),
            RequestId::Number(3),
        );
        let response = adapter.handle_initialize(&request).await.unwrap();
        let parsed = JsonRpcParser::parse_response(&response).unwrap();
        let result = parsed.result.unwrap();
        assert_eq!(result["protocolVersion"], "2025-06-18");
        // Client-side capabilities are not advertised as server capabilities.
        assert!(result["capabilities"]["roots"].is_null());
        assert!(result["capabilities"]["elicitation"].is_null());
    }

    #[tokio::test]
    async fn test_complete_adapter_prompts() {
        let mut adapter = CompleteMcpAdapter::new();
        adapter
            .register_prompt(
                PromptTemplate::new("greet", "Greeting prompt", "Hello {{name}}!").with_argument(
                    "name",
                    "Name to greet",
                    true,
                ),
            )
            .unwrap();

        let init = JsonRpcRequest::new(
            "initialize",
            Some(serde_json::json!({"capabilities": {"dcp": {"prompts": [0]}}})),
            RequestId::Number(0),
        );
        adapter.handle_initialize(&init).await.unwrap();
        adapter
            .handle_initialized(&JsonRpcRequest::notification(
                "notifications/initialized",
                None,
            ))
            .await
            .unwrap();

        // List prompts
        let request = JsonRpcRequest::new("prompts/list", None, RequestId::Number(1));
        let response = adapter.handle_prompts_list(&request).await.unwrap();
        let parsed = JsonRpcParser::parse_response(&response).unwrap();
        assert!(parsed.is_success());

        // Get prompt
        let request = JsonRpcRequest::new(
            "prompts/get",
            Some(serde_json::json!({"name": "greet", "arguments": {"name": "World"}})),
            RequestId::Number(2),
        );
        let response = adapter.handle_prompts_get(&request).await.unwrap();
        let parsed = JsonRpcParser::parse_response(&response).unwrap();
        assert!(parsed.is_success());
    }

    #[tokio::test]
    async fn test_notification_no_response() {
        let adapter = CompleteMcpAdapter::new();
        let router = BinaryTrieRouter::new();

        // Notification has no id
        let json = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
        let result = adapter.handle_request(json, &router).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_unknown_method() {
        let adapter = CompleteMcpAdapter::new();
        let router = BinaryTrieRouter::new();

        let json = r#"{"jsonrpc":"2.0","method":"unknown/method","id":1}"#;
        let result = adapter.handle_request(json, &router).await.unwrap();

        let response = JsonRpcParser::parse_response(&result.unwrap()).unwrap();
        assert!(response.is_error());
        assert_eq!(response.error.unwrap().code, -32601);
    }
}
