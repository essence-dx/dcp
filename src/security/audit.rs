//! Structured security audit receipts.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::json;

use super::redaction::{sanitize_field_key, sanitize_field_value, sanitize_text};

/// Default maximum number of in-memory security audit receipts retained.
pub const DEFAULT_MAX_SECURITY_AUDIT_EVENTS: usize = 1024;
/// Maximum bytes retained for any single audit text field.
pub const MAX_SECURITY_AUDIT_TEXT_LEN: usize = 256;

fn truncate_audit_text(value: &str) -> String {
    if value.len() <= MAX_SECURITY_AUDIT_TEXT_LEN {
        return value.to_string();
    }

    let mut truncated = String::with_capacity(MAX_SECURITY_AUDIT_TEXT_LEN);
    for ch in value.chars() {
        if truncated.len() + ch.len_utf8() > MAX_SECURITY_AUDIT_TEXT_LEN {
            break;
        }
        truncated.push(ch);
    }
    truncated
}

fn sanitize_audit_text(value: &str) -> String {
    truncate_audit_text(&sanitize_text(value))
}

fn sanitize_audit_field_key(key: &str) -> String {
    truncate_audit_text(&sanitize_field_key(key))
}

fn sanitize_audit_field_value(key: &str, value: &str) -> String {
    truncate_audit_text(&sanitize_field_value(key, value))
}

/// Security-relevant event category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityAuditAction {
    /// A request was rejected before normal dispatch.
    RequestRejected,
    /// A negotiated capability boundary denied access.
    CapabilityDenied,
    /// A parse or schema validation error rejected input.
    ValidationRejected,
    /// A replay guard denied a repeated or stale request.
    ReplayRejected,
    /// A signature check failed.
    SignatureRejected,
    /// A transport-level policy rejected input.
    TransportRejected,
    /// Shutdown policy denied new work.
    ShutdownRejected,
}

impl SecurityAuditAction {
    /// Stable receipt action name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RequestRejected => "request_rejected",
            Self::CapabilityDenied => "capability_denied",
            Self::ValidationRejected => "validation_rejected",
            Self::ReplayRejected => "replay_rejected",
            Self::SignatureRejected => "signature_rejected",
            Self::TransportRejected => "transport_rejected",
            Self::ShutdownRejected => "shutdown_rejected",
        }
    }
}

/// Structured audit receipt for a security-relevant decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityAuditEvent {
    /// Event timestamp in Unix milliseconds.
    pub timestamp: u64,
    /// Security action category.
    pub action: SecurityAuditAction,
    /// Stable reason code.
    pub reason: String,
    /// Optional protocol method.
    pub method: Option<String>,
    /// Optional request identifier.
    pub request_id: Option<String>,
    /// Additional redacted fields.
    pub fields: HashMap<String, String>,
}

impl SecurityAuditEvent {
    /// Create a new audit event.
    pub fn new(action: SecurityAuditAction, reason: impl Into<String>) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        Self {
            timestamp,
            action,
            reason: sanitize_audit_text(&reason.into()),
            method: None,
            request_id: None,
            fields: HashMap::new(),
        }
    }

    /// Attach a protocol method.
    pub fn with_method(mut self, method: impl Into<String>) -> Self {
        self.method = Some(sanitize_audit_text(&method.into()));
        self
    }

    /// Attach a request identifier.
    pub fn with_request_id(mut self, request_id: impl Into<String>) -> Self {
        self.request_id = Some(sanitize_audit_text(&request_id.into()));
        self
    }

    /// Attach a redacted field.
    pub fn with_field(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        let key = key.into();
        let value = value.into();
        let sanitized_key = sanitize_audit_field_key(&key);
        self.fields
            .insert(sanitized_key, sanitize_audit_field_value(&key, &value));
        self
    }

    fn sanitized_copy(&self) -> Self {
        let mut fields = HashMap::new();
        for (key, value) in &self.fields {
            fields.insert(
                sanitize_audit_field_key(key),
                sanitize_audit_field_value(key, value),
            );
        }

        Self {
            timestamp: self.timestamp,
            action: self.action,
            reason: sanitize_audit_text(&self.reason),
            method: self
                .method
                .as_ref()
                .map(|method| sanitize_audit_text(method)),
            request_id: self
                .request_id
                .as_ref()
                .map(|request_id| sanitize_audit_text(request_id)),
            fields,
        }
    }

    /// Render as JSON for durable receipts.
    pub fn to_json(&self) -> String {
        let event = self.sanitized_copy();
        let mut value = json!({
            "timestamp": event.timestamp,
            "action": event.action.as_str(),
            "reason": event.reason,
            "fields": event.fields,
        });

        if let Some(method) = &event.method {
            value["method"] = json!(method);
        }
        if let Some(request_id) = &event.request_id {
            value["request_id"] = json!(request_id);
        }

        serde_json::to_string(&value).unwrap_or_else(|_| "{}".to_string())
    }
}

#[derive(Debug, Default)]
struct SecurityAuditState {
    events: Vec<SecurityAuditEvent>,
    dropped_count: u64,
}

/// Bounded in-memory audit log used by adapters and tests.
#[derive(Debug, Clone)]
pub struct SecurityAuditLog {
    state: Arc<RwLock<SecurityAuditState>>,
    max_events: usize,
}

impl SecurityAuditLog {
    /// Create an empty audit log.
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_MAX_SECURITY_AUDIT_EVENTS)
    }

    /// Create an empty audit log with a maximum retained event count.
    pub fn with_capacity(max_events: usize) -> Self {
        Self {
            state: Arc::new(RwLock::new(SecurityAuditState::default())),
            max_events,
        }
    }

    /// Append an event.
    pub fn record(&self, event: SecurityAuditEvent) {
        if let Ok(mut state) = self.state.write() {
            let event = event.sanitized_copy();
            if self.max_events == 0 {
                state.dropped_count = state.dropped_count.saturating_add(1);
                return;
            }

            if state.events.len() >= self.max_events {
                state.events.remove(0);
                state.dropped_count = state.dropped_count.saturating_add(1);
            }
            state.events.push(event);
        }
    }

    /// Snapshot events.
    pub fn events(&self) -> Vec<SecurityAuditEvent> {
        self.state
            .read()
            .map(|state| state.events.clone())
            .unwrap_or_default()
    }

    /// Number of receipts dropped because the retention bound was reached.
    pub fn dropped_count(&self) -> u64 {
        self.state
            .read()
            .map(|state| state.dropped_count)
            .unwrap_or_default()
    }

    /// Clear events.
    pub fn clear(&self) {
        if let Ok(mut state) = self.state.write() {
            state.events.clear();
            state.dropped_count = 0;
        }
    }
}

impl Default for SecurityAuditLog {
    fn default() -> Self {
        Self::new()
    }
}
