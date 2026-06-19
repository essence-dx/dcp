//! Server-Sent Events (SSE) transport for MCP compatibility.
//!
//! Provides HTTP SSE handling and event stream formatting for MCP clients.
//! Supports reconnection with Last-Event-ID for event replay.

use std::collections::VecDeque;
use std::fmt::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use crate::security::{sanitize_json_value, sanitize_text};

use super::json_rpc::{JsonRpcParser, JsonRpcRequest, RequestId, DEFAULT_MAX_JSONRPC_REQUEST_SIZE};

/// Default maximum number of queued SSE POST messages.
pub const DEFAULT_MAX_SSE_PENDING_RESPONSES: usize = 1024;
/// Default maximum aggregate bytes retained in the SSE POST queue.
pub const DEFAULT_MAX_SSE_PENDING_RESPONSE_BYTES: usize =
    DEFAULT_MAX_JSONRPC_REQUEST_SIZE * DEFAULT_MAX_SSE_PENDING_RESPONSES;

/// Errors returned by checked SSE replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SseReplayError {
    /// Requested event ID has already been evicted from the replay buffer.
    StaleEventId,
    /// Requested event ID is newer than the latest retained event.
    FutureEventId,
}

/// SSE event types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SseEventType {
    /// JSON-RPC message event
    Message,
    /// Endpoint information event
    Endpoint,
    /// Error event
    Error,
    /// Ping/keepalive event
    Ping,
}

impl SseEventType {
    /// Get the event type string
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Message => "message",
            Self::Endpoint => "endpoint",
            Self::Error => "error",
            Self::Ping => "ping",
        }
    }
}

/// SSE event for streaming
#[derive(Debug, Clone)]
pub struct SseEvent {
    /// Event type
    pub event_type: SseEventType,
    /// Event data (JSON payload)
    pub data: String,
    /// Optional event ID
    pub id: Option<String>,
    /// Optional retry interval in milliseconds
    pub retry: Option<u32>,
}

impl SseEvent {
    /// Create a new message event
    pub fn message(data: String) -> Self {
        Self {
            event_type: SseEventType::Message,
            data,
            id: None,
            retry: None,
        }
    }

    /// Create a new endpoint event
    pub fn endpoint(url: String) -> Self {
        Self {
            event_type: SseEventType::Endpoint,
            data: url,
            id: None,
            retry: None,
        }
    }

    /// Create a new error event
    pub fn error(message: String) -> Self {
        Self {
            event_type: SseEventType::Error,
            data: sanitize_text(&message),
            id: None,
            retry: None,
        }
    }

    /// Create a ping event
    pub fn ping() -> Self {
        Self {
            event_type: SseEventType::Ping,
            data: String::new(),
            id: None,
            retry: None,
        }
    }

    /// Set the event ID
    pub fn with_id(mut self, id: String) -> Self {
        self.id = Some(sanitize_sse_field(&id));
        self
    }

    /// Set the retry interval
    pub fn with_retry(mut self, retry_ms: u32) -> Self {
        self.retry = Some(retry_ms);
        self
    }

    /// Format the event as SSE text
    pub fn format(&self) -> String {
        let mut output = String::new();

        // Event type
        let _ = writeln!(output, "event: {}", self.event_type.as_str());

        // Event ID if present
        if let Some(ref id) = self.id {
            let _ = writeln!(output, "id: {}", sanitize_sse_field(id));
        }

        // Retry if present
        if let Some(retry) = self.retry {
            let _ = writeln!(output, "retry: {}", retry);
        }

        // Data lines (split by newlines)
        let data = sanitize_sse_data(&self.data);
        for line in data.lines() {
            let _ = writeln!(output, "data: {}", line);
        }

        // Empty data line if no data
        if data.is_empty() {
            let _ = writeln!(output, "data:");
        }

        // Blank line to end event
        let _ = writeln!(output);

        output
    }

    /// Get the numeric ID if present
    pub fn numeric_id(&self) -> Option<u64> {
        self.id.as_ref().and_then(|id| id.parse().ok())
    }
}

/// Buffered event for replay
#[derive(Debug, Clone)]
struct BufferedEvent {
    /// Event ID
    id: u64,
    /// Formatted event data
    formatted: String,
}

fn sanitize_replay_payload(json: &str) -> String {
    serde_json::from_str::<serde_json::Value>(json)
        .ok()
        .and_then(|value| {
            let sanitized = sanitize_json_value(&value);
            if sanitized == value {
                Some(json.to_string())
            } else {
                serde_json::to_string(&sanitized).ok()
            }
        })
        .unwrap_or_else(|| sanitize_text(json))
}

fn sanitize_sse_field(value: &str) -> String {
    sanitize_text(value)
        .chars()
        .map(|ch| if matches!(ch, '\r' | '\n') { ' ' } else { ch })
        .collect()
}

fn sanitize_sse_data(value: &str) -> String {
    sanitize_replay_payload(value)
        .replace("\r\n", "\n")
        .replace('\r', "\n")
}

/// Event buffer for reconnection replay
#[derive(Debug)]
pub struct EventBuffer {
    /// Buffered events
    events: VecDeque<BufferedEvent>,
    /// Maximum buffer size
    max_size: usize,
}

impl EventBuffer {
    /// Create a new event buffer
    pub fn new(max_size: usize) -> Self {
        Self {
            events: VecDeque::with_capacity(max_size.min(1000)),
            max_size,
        }
    }

    /// Add an event to the buffer
    pub fn push(&mut self, id: u64, formatted: String) {
        if self.max_size == 0 {
            return;
        }

        // Remove oldest if at capacity
        while self.events.len() >= self.max_size {
            self.events.pop_front();
        }
        self.events.push_back(BufferedEvent { id, formatted });
    }

    /// Get events after a given ID for replay
    pub fn events_after(&self, last_id: u64) -> Vec<String> {
        self.events
            .iter()
            .filter(|e| e.id > last_id)
            .map(|e| e.formatted.clone())
            .collect()
    }

    /// Get the latest event ID
    pub fn latest_id(&self) -> Option<u64> {
        self.events.back().map(|e| e.id)
    }

    /// Get the oldest retained event ID.
    pub fn oldest_id(&self) -> Option<u64> {
        self.events.front().map(|e| e.id)
    }

    /// Get buffer size
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Check if buffer is empty
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Clear the buffer
    pub fn clear(&mut self) {
        self.events.clear();
    }
}

/// SSE transport handler with reconnection support
pub struct SseTransport {
    /// Event counter for IDs
    event_counter: AtomicU64,
    /// Default retry interval
    default_retry_ms: u32,
    /// Event buffer for replay
    buffer: Arc<RwLock<EventBuffer>>,
}

impl Default for SseTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl SseTransport {
    /// Create a new SSE transport
    pub fn new() -> Self {
        Self::with_buffer_size(100)
    }

    /// Create with custom buffer size
    pub fn with_buffer_size(buffer_size: usize) -> Self {
        Self {
            event_counter: AtomicU64::new(0),
            default_retry_ms: 3000,
            buffer: Arc::new(RwLock::new(EventBuffer::new(buffer_size))),
        }
    }

    /// Set the default retry interval
    pub fn with_retry(mut self, retry_ms: u32) -> Self {
        self.default_retry_ms = retry_ms;
        self
    }

    /// Get the content type header for SSE
    pub fn content_type() -> &'static str {
        "text/event-stream"
    }

    /// Get required headers for SSE response
    pub fn headers() -> Vec<(&'static str, &'static str)> {
        vec![
            ("Content-Type", "text/event-stream"),
            ("Cache-Control", "no-cache"),
            ("Connection", "keep-alive"),
        ]
    }

    /// Get the next event ID
    fn next_id(&self) -> u64 {
        self.event_counter.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// Format a JSON-RPC response as an SSE event
    pub fn format_response(&self, json: &str) -> String {
        let id = self.next_id();
        let event = SseEvent::message(json.to_string())
            .with_id(id.to_string())
            .with_retry(self.default_retry_ms);
        let formatted = event.format();

        let replay_event = SseEvent::message(sanitize_replay_payload(json))
            .with_id(id.to_string())
            .with_retry(self.default_retry_ms);
        let replay_formatted = replay_event.format();

        // Buffer a sanitized copy for replay.
        if let Ok(mut buffer) = self.buffer.write() {
            buffer.push(id, replay_formatted);
        }

        formatted
    }

    /// Format an error as an SSE event
    pub fn format_error(&self, message: &str) -> String {
        let id = self.next_id();
        let event = SseEvent::error(sanitize_text(message)).with_id(id.to_string());
        let formatted = event.format();

        // Buffer for replay
        if let Ok(mut buffer) = self.buffer.write() {
            buffer.push(id, formatted.clone());
        }

        formatted
    }

    /// Format a ping/keepalive event (not buffered)
    pub fn format_ping(&self) -> String {
        SseEvent::ping().format()
    }

    /// Format an endpoint event (for initial connection)
    pub fn format_endpoint(&self, url: &str) -> String {
        let id = self.next_id();
        let event = SseEvent::endpoint(sanitize_text(url)).with_id(id.to_string());
        event.format()
    }

    /// Parse Last-Event-ID header to resume from
    pub fn parse_last_event_id(header: &str) -> Option<u64> {
        header.trim().parse().ok()
    }

    /// Get events for replay after reconnection
    pub fn get_replay_events(&self, last_event_id: u64) -> Vec<String> {
        if let Ok(buffer) = self.buffer.read() {
            buffer.events_after(last_event_id)
        } else {
            Vec::new()
        }
    }

    /// Get replay events with explicit stale/future cursor handling.
    pub fn checked_replay_events(&self, last_event_id: u64) -> Result<Vec<String>, SseReplayError> {
        let buffer = self
            .buffer
            .read()
            .map_err(|_| SseReplayError::StaleEventId)?;

        if buffer.is_empty() {
            let current = self.current_event_id();
            if last_event_id > current {
                return Err(SseReplayError::FutureEventId);
            }
            if current > 0 && last_event_id < current {
                return Err(SseReplayError::StaleEventId);
            }
            return Ok(Vec::new());
        }

        if let Some(latest) = buffer.latest_id() {
            if last_event_id > latest {
                return Err(SseReplayError::FutureEventId);
            }
        }

        if let Some(oldest) = buffer.oldest_id() {
            if last_event_id < oldest.saturating_sub(1) {
                return Err(SseReplayError::StaleEventId);
            }
        }

        Ok(buffer.events_after(last_event_id))
    }

    /// Get the current event counter value
    pub fn current_event_id(&self) -> u64 {
        self.event_counter.load(Ordering::SeqCst)
    }

    /// Get buffer statistics
    pub fn buffer_stats(&self) -> (usize, Option<u64>) {
        if let Ok(buffer) = self.buffer.read() {
            (buffer.len(), buffer.latest_id())
        } else {
            (0, None)
        }
    }

    /// Reset event counter and clear buffer (for testing)
    pub fn reset(&self) {
        self.event_counter.store(0, Ordering::SeqCst);
        if let Ok(mut buffer) = self.buffer.write() {
            buffer.clear();
        }
    }
}

/// HTTP POST message handler for SSE transport
pub struct SseMessageHandler {
    /// Pending responses to send
    responses: Arc<RwLock<VecDeque<String>>>,
    /// Maximum accepted JSON-RPC request size in bytes.
    max_message_size: usize,
    /// Maximum number of queued pending responses.
    max_pending_responses: usize,
    /// Maximum aggregate bytes queued in pending responses.
    max_pending_response_bytes: usize,
}

impl Default for SseMessageHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl SseMessageHandler {
    /// Create a new message handler
    pub fn new() -> Self {
        Self {
            responses: Arc::new(RwLock::new(VecDeque::new())),
            max_message_size: DEFAULT_MAX_JSONRPC_REQUEST_SIZE,
            max_pending_responses: DEFAULT_MAX_SSE_PENDING_RESPONSES,
            max_pending_response_bytes: DEFAULT_MAX_SSE_PENDING_RESPONSE_BYTES,
        }
    }

    /// Set maximum accepted JSON-RPC request size for POST messages.
    pub fn with_max_message_size(mut self, max_message_size: usize) -> Self {
        self.max_message_size = max_message_size;
        self
    }

    /// Set maximum number of queued POST messages.
    pub fn with_max_pending_responses(mut self, max_pending_responses: usize) -> Self {
        self.max_pending_responses = max_pending_responses;
        self
    }

    /// Set maximum aggregate bytes queued by POST messages.
    pub fn with_max_pending_response_bytes(mut self, max_pending_response_bytes: usize) -> Self {
        self.max_pending_response_bytes = max_pending_response_bytes;
        self
    }

    /// Handle an incoming POST message
    pub fn handle_message(&self, json: &str) -> Result<(), String> {
        let request = JsonRpcParser::parse_request_with_limit(json, self.max_message_size)
            .map_err(|_| "Invalid JSON-RPC request".to_string())?;
        if !is_supported_sse_post_method(&request.method) {
            return Err("Unsupported JSON-RPC method on SSE POST".to_string());
        }
        validate_supported_sse_notification(&request)?;
        let notification_only = is_supported_sse_notification(&request.method);
        if request.is_notification() && !notification_only {
            return Err("JSON-RPC notification not accepted on SSE POST".to_string());
        }
        if !request.is_notification() && notification_only {
            return Err("JSON-RPC notification method must not include id".to_string());
        }
        if request.is_notification() {
            return Ok(());
        }

        // Queue response (in real implementation, this would process the request).
        let mut responses = self
            .responses
            .write()
            .map_err(|_| "SSE response queue unavailable".to_string())?;
        if responses.len() >= self.max_pending_responses {
            return Err("SSE response queue full".to_string());
        }
        let sanitized = sanitize_replay_payload(json);
        let queued_bytes = responses.iter().fold(0usize, |total, response| {
            total.saturating_add(response.len())
        });
        if queued_bytes.saturating_add(sanitized.len()) > self.max_pending_response_bytes {
            return Err("SSE response queue byte budget exceeded".to_string());
        }
        responses.push_back(sanitized);

        Ok(())
    }

    /// Get pending responses
    pub fn take_responses(&self) -> Vec<String> {
        if let Ok(mut responses) = self.responses.write() {
            responses.drain(..).collect()
        } else {
            Vec::new()
        }
    }

    /// Check if there are pending responses
    pub fn has_pending(&self) -> bool {
        if let Ok(responses) = self.responses.read() {
            !responses.is_empty()
        } else {
            false
        }
    }
}

fn is_supported_sse_notification(method: &str) -> bool {
    matches!(
        method,
        "notifications/initialized" | "notifications/cancelled"
    )
}

fn validate_supported_sse_notification(request: &JsonRpcRequest) -> Result<(), String> {
    if request.method == "notifications/initialized" {
        return if request.params.is_none() {
            Ok(())
        } else {
            Err("Invalid JSON-RPC notification params".to_string())
        };
    }

    if request.method != "notifications/cancelled" {
        return Ok(());
    }

    let params = request
        .params
        .as_ref()
        .and_then(|params| params.as_object())
        .ok_or_else(|| "Invalid JSON-RPC notification params".to_string())?;
    if params
        .keys()
        .any(|key| key != "requestId" && key != "reason")
    {
        return Err("Invalid JSON-RPC notification params".to_string());
    }

    let request_id = params
        .get("requestId")
        .ok_or_else(|| "Invalid JSON-RPC notification params".to_string())?;

    RequestId::try_from_json_value(request_id)
        .map_err(|_| "Invalid JSON-RPC notification params".to_string())?;

    if params
        .get("reason")
        .is_some_and(|reason| !reason.is_string())
    {
        return Err("Invalid JSON-RPC notification params".to_string());
    }

    Ok(())
}

fn is_supported_sse_post_method(method: &str) -> bool {
    matches!(
        method,
        "initialize"
            | "ping"
            | "tools/list"
            | "tools/call"
            | "resources/list"
            | "resources/read"
            | "resources/subscribe"
            | "resources/unsubscribe"
            | "prompts/list"
            | "prompts/get"
            | "logging/setLevel"
            | "completion/complete"
    ) || is_supported_sse_notification(method)
}

/// SSE endpoint configuration
#[derive(Debug, Clone)]
pub struct SseEndpointConfig {
    /// Path for SSE event stream (GET)
    pub events_path: String,
    /// Path for client messages (POST)
    pub messages_path: String,
    /// Ping interval in seconds
    pub ping_interval_secs: u64,
    /// Event buffer size
    pub buffer_size: usize,
    /// Default retry interval in milliseconds
    pub retry_ms: u32,
}

impl Default for SseEndpointConfig {
    fn default() -> Self {
        Self {
            events_path: "/events".to_string(),
            messages_path: "/message".to_string(),
            ping_interval_secs: 30,
            buffer_size: 100,
            retry_ms: 3000,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sse_event_format_message() {
        let event = SseEvent::message(r#"{"jsonrpc":"2.0","result":{},"id":1}"#.to_string());
        let formatted = event.format();

        assert!(formatted.contains("event: message"));
        assert!(formatted.contains(r#"data: {"jsonrpc":"2.0","result":{},"id":1}"#));
        assert!(formatted.ends_with("\n\n"));
    }

    #[test]
    fn test_sse_event_with_id_and_retry() {
        let event = SseEvent::message("test".to_string())
            .with_id("42".to_string())
            .with_retry(5000);
        let formatted = event.format();

        assert!(formatted.contains("id: 42"));
        assert!(formatted.contains("retry: 5000"));
    }

    #[test]
    fn test_sse_event_multiline_data() {
        let event = SseEvent::message("line1\nline2\nline3".to_string());
        let formatted = event.format();

        assert!(formatted.contains("data: line1"));
        assert!(formatted.contains("data: line2"));
        assert!(formatted.contains("data: line3"));
    }

    #[test]
    fn test_sse_transport_format_response() {
        let transport = SseTransport::new();
        let response = transport.format_response(r#"{"result":"ok"}"#);

        assert!(response.contains("event: message"));
        assert!(response.contains("id: 1"));
        assert!(response.contains("retry: 3000"));
        assert!(response.contains(r#"data: {"result":"ok"}"#));
    }

    #[test]
    fn test_sse_transport_format_error() {
        let transport = SseTransport::new();
        let error = transport.format_error("Something went wrong");

        assert!(error.contains("event: error"));
        assert!(error.contains("data: Something went wrong"));
    }

    #[test]
    fn test_sse_transport_format_ping() {
        let transport = SseTransport::new();
        let ping = transport.format_ping();

        assert!(ping.contains("event: ping"));
        assert!(ping.contains("data:"));
    }

    #[test]
    fn test_sse_transport_headers() {
        let headers = SseTransport::headers();

        assert!(headers.contains(&("Content-Type", "text/event-stream")));
        assert!(headers.contains(&("Cache-Control", "no-cache")));
        assert!(headers.contains(&("Connection", "keep-alive")));
    }

    #[test]
    fn test_parse_last_event_id() {
        assert_eq!(SseTransport::parse_last_event_id("42"), Some(42));
        assert_eq!(SseTransport::parse_last_event_id("  100  "), Some(100));
        assert_eq!(SseTransport::parse_last_event_id("invalid"), None);
    }

    #[test]
    fn test_sse_event_types() {
        assert_eq!(SseEventType::Message.as_str(), "message");
        assert_eq!(SseEventType::Endpoint.as_str(), "endpoint");
        assert_eq!(SseEventType::Error.as_str(), "error");
        assert_eq!(SseEventType::Ping.as_str(), "ping");
    }

    #[test]
    fn test_event_buffer() {
        let mut buffer = EventBuffer::new(3);

        buffer.push(1, "event1".to_string());
        buffer.push(2, "event2".to_string());
        buffer.push(3, "event3".to_string());

        assert_eq!(buffer.len(), 3);
        assert_eq!(buffer.latest_id(), Some(3));

        // Get events after ID 1
        let events = buffer.events_after(1);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0], "event2");
        assert_eq!(events[1], "event3");

        // Add one more, should evict oldest
        buffer.push(4, "event4".to_string());
        assert_eq!(buffer.len(), 3);
        assert_eq!(buffer.latest_id(), Some(4));

        // Event 1 should be gone
        let events = buffer.events_after(0);
        assert_eq!(events.len(), 3);
        assert!(!events.contains(&"event1".to_string()));
    }

    #[test]
    fn test_sse_transport_replay() {
        let transport = SseTransport::with_buffer_size(10);

        // Send some events
        transport.format_response(r#"{"id":1}"#);
        transport.format_response(r#"{"id":2}"#);
        transport.format_response(r#"{"id":3}"#);

        // Get replay events after ID 1
        let replay = transport.get_replay_events(1);
        assert_eq!(replay.len(), 2);

        // Get all events
        let all = transport.get_replay_events(0);
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn test_sse_message_handler() {
        let handler = SseMessageHandler::new();

        // Handle valid message
        assert!(handler
            .handle_message(r#"{"jsonrpc":"2.0","method":"ping","id":1}"#)
            .is_ok());
        assert!(handler.has_pending());

        // Handle invalid message
        assert!(handler.handle_message("not json").is_err());

        // Take responses
        let responses = handler.take_responses();
        assert_eq!(responses.len(), 1);
        assert!(!handler.has_pending());
    }
}
