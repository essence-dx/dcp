
# DCP - Development Context Protocol

A high-performance binary protocol designed to replace MCP (Model Context Protocol) with 10-1000x performance improvements while maintaining full backward compatibility.

## Why DCP?

+---------+--------+-----------+
| Metric  | MCP    | (JSON-RPC |
+=========+========+===========+
| Message | Header | ~100+     |
+---------+--------+-----------+



## Features

- Binary Message Envelope (BME)
- 8-byte fixed header with O(1) parsing via pointer casting
- Zero-Copy Tool Invocation
- Direct memory access without serialization overhead
- O(1) Binary Trie Router
- Constant-time tool dispatch by ID
- Lock-Free Streaming
- Ring buffer with backpressure signaling
- XOR Delta Sync
- Efficient state synchronization with run-length encoding
- Ed25519 Security
- Signed tool definitions and replay protection
- Full MCP Compatibility
- JSON-RPC adapter for seamless migration

## Architecture

+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| ┌─────────────────────────────────────────────────────────────────────────┐                                                                                                                                                       |
+===================================================================================================================================================================================================================================+
| │DCP                                                                                                                                                                                                                              |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+



## Installation

Add to your `Cargo.toml`:
```toml
[dependencies]
dcp = "0.1.0"
```
Or build from source:
```bash
git clone https://github.com/your-org/dcp.git cd dcp cargo build --release ```


## Quick Start



### As a Library


```rust
use dcp::{ DcpServer, ServerConfig, McpAdapter, BinaryMessageEnvelope, MessageType, Flags, };
// Create a DCP server let config = ServerConfig::default();
let server = DcpServer::new(config);
// Handle MCP requests (backward compatible)
let adapter = McpAdapter::new();
let response = adapter.handle_request(json_rpc_request)?;
// Or use native binary protocol let envelope = BinaryMessageEnvelope::new( MessageType::Tool, Flags::empty(), payload.len() as u32, );
```


### CLI Usage


```bash

# Start DCP server

dcp serve --port 8080

# Convert MCP schema to DCP

dcp convert --input mcp-schema.json --output dcp-schema.bin

# Show protocol info

dcp info

# Validate a DCP message

dcp validate message.bin ```

## Core Components

### Binary Message Envelope

8-byte header for all DCP messages:
```rust


#[repr(C, packed)]


pub struct BinaryMessageEnvelope { pub magic: u16, // 0xDC01 for DCP v1 pub message_type: u8, // Tool, Resource, Prompt, Response, Error, Stream pub flags: u8, // streaming, compressed, signed pub payload_len: u32, // Payload length in bytes }
```

### Tool Invocation

Zero-copy tool calls:
```rust


#[repr(C)]


pub struct ToolInvocation { pub tool_id: u32, // Pre-resolved tool ID pub arg_layout: u64, // Argument type bitfield pub args_offset: u32, // Offset in shared memory pub args_len: u32, // Argument length }
```

### Capability Manifest

Bitset-based capability negotiation:
```rust
let manifest = CapabilityManifest::new();
manifest.set_tool(42, true);
manifest.set_resource(7, true);
// O(1) capability intersection let common = client_manifest.intersect(&server_manifest);
```

## MCP Migration Guide

DCP provides seamless migration from MCP: -Drop-in Adapter: Use `McpAdapter` to handle JSON-RPC requests -Hybrid Mode: Run both protocols simultaneously during transition -Schema Conversion: Use `dcp convert` to migrate tool schemas -Session Preservation: Upgrade connections without losing state ```rust // Existing MCP handler let mcp_request = r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"read_file"},"id":1}"#;
// Works with DCP adapter let adapter = McpAdapter::new();
let response = adapter.handle_request(mcp_request)?;
```


## Testing


DCP includes comprehensive testing with 263 tests:
```bash

# Run all tests

cargo test --release

# Run property-based tests only

cargo test props --release

# Run with verbose output

cargo test --release -- --nocapture ```
Test coverage includes: -150 unit tests for specific functionality -113 property-based tests using `proptest` -16 correctness properties validated

## Performance

Benchmarks comparing DCP vs MCP JSON-RPC:
```bash
cargo bench ```
Key metrics: -Message size: 6-12x smaller than JSON-RPC -Parsing: O(1) pointer cast vs O(n) JSON parsing -Memory: Zero allocations for message handling -Dispatch: O(1) tool routing by ID


## Security


- Ed25519 Signatures: Tool definitions and invocations can be cryptographically signed
- Replay Protection: Nonce-based protection with timestamp expiration
- Capability Manifests: Fine-grained permission control via bitsets

### Security Evidence

Current regression coverage verifies these hardening behaviors:

- Capability negotiation is least-privilege and rejects unnegotiated tool access.
- Complete MCP initialization intersects client-declared DCP capability ids with the registered server manifest instead of advertising the server manifest by default, can further restrict negotiated tool access with a server-side authorization policy, rejects conflicting DCP capability declarations, rejects out-of-range DCP capability ids, rejects non-object initialize params and DCP capability shapes, and does not consume the session's one allowed initialize attempt on malformed capability negotiation.
- Complete MCP `tools/list` filters out unnegotiated tool ids instead of leaking every registered tool once any tool is granted.
- Complete MCP `tools/list` publishes registered handler input schemas for negotiated tools, and `tools/call` translates JSON arguments through those schemas before dispatch.
- Complete MCP `tools/list` and `tools/call` reject unnegotiated access even when their public handlers are called directly; `tools/call` rejects wrong-typed or undeclared JSON arguments with `Invalid params`, returns the same capability-denied error shape for unknown and unnegotiated tool names, records one denial receipt for a denied call, and rejects params arrays, scalar `_meta`, plus unexpected top-level `tools/call` params before dispatch without echoing tested secret-bearing extra fields.
- Complete MCP `resources/list`, `resources/read`, `prompts/list`, `prompts/get`, and `completion/complete` enforce tested negotiated resource/prompt ids instead of treating one category bit as access to every registered object; direct `resources/list` and `prompts/list` handlers deny unnegotiated access, `resources/read`, `prompts/get`, and `completion/complete` return the same capability-denied error shape for unknown and unnegotiated resource/prompt references, and `prompts/get` rejects undeclared prompt arguments and non-string prompt argument values.
- Complete and legacy MCP tool registration, plus Complete MCP resource/prompt registration, fail closed at the manifest capacity boundary instead of creating ungrantable capability ids; duplicate tool names/ids and duplicate Complete MCP prompt names are rejected instead of silently remapping existing capability bindings.
- Binary trie router registration rejects out-of-range tool ids and duplicate tool names/ids before mutating dispatch or name-resolution tables.
- MCP adapter capability advertising is based on registered tools, resources, and prompts; the legacy adapter advertises tools only when tools are registered and does not advertise unsupported resources/prompts.
- Legacy MCP adapter `tools/list` and `tools/call` are deny-by-default until a negotiated capability manifest is attached, direct legacy tool calls return explicit capability-denied JSON-RPC errors without executing handlers, denied legacy `tools/list` and `tools/call` paths record structured capability-denied receipts, unknown and unnegotiated legacy tool calls have the same error shape without echoing secret-bearing tool names, legacy malformed and oversized JSON-RPC requests return explicit JSON-RPC errors with structured validation receipts instead of escaping as adapter errors, malformed legacy `tools/call` params, missing direct `tools/call` params/name, and schema-validation failures are rejected before dispatch with validation receipts, unknown legacy methods and top-level legacy notifications record request-rejected receipts without echoing tested secret-bearing method or metadata text, direct legacy `initialize`, `tools/list`, and `tools/call` handlers require the exact method plus a request id before returning success, listing tools, parsing params, or dispatching, and legacy direct-handler notifications are rejected before success, listing, or dispatch.
- Legacy MCP `tools/call` request params are strict objects with only `name`, optional `arguments`, and optional object `_meta`; params arrays, unexpected top-level params, scalar `_meta`, scalar arguments, and non-empty object arguments are rejected before dispatch, while omitted or empty-object arguments normalize to an empty raw argument payload.
- Raw `DcpServer::invoke` and `invoke_by_name` deny execution by default, record sanitized capability-denied receipts for denied raw invocation attempts, and require negotiated capability-aware invocation for server-side tool execution.
- Raw `BinaryTrieRouter::execute` denies execution by default, raw dispatch is crate-internal, and Complete MCP tool calls use negotiated capability-aware invocation.
- `BinaryTrieRouter::execute_signed_authorized` and `DcpServer::invoke_signed_authorized` provide a tested authenticated dispatch boundary that verifies Ed25519 invocation signatures, argument hashes, negotiated tool capability, schema validation, and replay freshness before handler execution; valid signed attempts are recorded in the replay guard before later capability/schema denials so the same signed invocation cannot be retried after permissions broaden.
- Complete MCP rejects repeated `initialize` calls so a session cannot expand its negotiated DCP capability manifest after the first negotiation.
- Complete and legacy MCP `tools/call` reject replayed side-effecting request ids within the adapter session after method-specific request validation, return explicit `request_replay` receipts, and do not dispatch the replayed call.
- Complete MCP inbound initialization rejects explicit unsupported `protocolVersion` values with `Invalid params` before consuming the one allowed initialize attempt, while still accepting a later supported protocol version on that adapter instance.
- Complete MCP request handling accepts the spec `notifications/initialized` lifecycle notification after a successful `initialize`, rejects the legacy `initialized` alias without completing lifecycle, rejects initialized notifications with request ids or params, rejects early or duplicate initialized notifications with structured lifecycle receipts, rejects unknown notification methods before dispatch, rejects request ids on notification-only methods, validates nested `notifications/cancelled` request ids with the same oversized and secret-bearing string-id hardening used for top-level JSON-RPC ids, rejects unsupported `notifications/cancelled` params before mutating cancellation state, redacts stored cancellation reasons, and does not execute side-effecting tool calls sent as notifications.
- Complete MCP rejects remote shutdown-shaped requests and notifications such as `shutdown`, `exit`, `terminate`, `server/shutdown`, and `notifications/shutdown` without changing adapter lifecycle state, and records structured `shutdown_rejected` receipts.
- Complete MCP rejects normal operational request methods until `notifications/initialized` completes the lifecycle handshake after `initialize`; the same readiness guard is enforced by the public direct handlers for tools, resources, prompts, completion, logging, sampling, roots, and elicitation; public direct request handlers require their exact JSON-RPC method and request id before parsing params or mutating adapter state, including direct initialize, ping, roots, elicitation, resource read/subscribe/unsubscribe, prompt get, logging, sampling, and completion paths.
- Complete MCP initialize responses omit tested client-side `roots` and `elicitation` capabilities from server capability advertisements, and resource capability advertisements only set `subscribe: true` when a negotiated resource handler explicitly supports subscriptions.
- Complete MCP rejects inbound client-originated `roots/list`, `sampling/createMessage`, and `elicitation/create` after initialization with method-not-found semantics, records `server_to_client_method` receipts, and does not echo tested root, sampling, or elicitation payload secrets.
- Complete MCP `completion/complete` rejects malformed or missing completion params with sanitized `Invalid params` errors, denies unnegotiated prompt/resource refs, rejects prompt argument names not declared by the referenced prompt, and applies configured roots to resource refs.
- Complete MCP resource reads and unsubscribes reject file URIs outside configured roots, empty roots deny `file://` resources by default, `resources/list` filters concrete resource metadata to configured roots, and `resources/list` filters resource templates to the negotiated resource handler ids.
- Complete MCP `resources/subscribe` rejects missing concrete resources and handlers that do not explicitly support subscriptions before adding subscription tracker state; the subscription tracker deduplicates repeated subscribers and enforces a tested per-resource subscriber cap.
- Resource URI template matching requires trailing literal template parts to match through the end of the URI, preventing suffix-appended matches for tested literal templates.
- Complete MCP, legacy MCP adapter, and SSE POST parsing use configurable request-size limits at adapter entry points.
- JSON-RPC parsing rejects malformed ids, oversized string request/response ids, secret-bearing string request ids, duplicate object fields, unknown top-level request/response envelope fields, reserved `rpc.*` methods, unsupported batch arrays, default-limit oversized request/response payloads, response-shaped request objects, response objects with request-only fields, scalar params, null params, and invalid response shapes.
- Complete MCP rejects unsupported JSON-RPC batch arrays with one `Invalid request` response using `id:null`, records a `batch_unsupported` validation receipt, and does not dispatch inner requests from the rejected batch.
- Fixed-size binary tool invocation and signed records parse from canonical little-endian field offsets instead of raw struct-memory casts, reject non-zero reserved padding and trailing bytes, serialize reserved padding as zero, and expose compact signature payload bytes that do not include reserved padding.
- DCP message parsing rejects unknown message types, reserved envelope flag bits, trailing bytes after the declared payload, and truncated declared payloads before returning a parsed message for dispatch.
- Shared binary argument layouts are validated against input schemas before dispatch, including required fields, type mismatches, out-of-bounds fields, non-empty raw payloads for empty schemas, and trailing bytes beyond declared schema fields.
- Nonce replay storage reports capacity exhaustion instead of silently accepting untracked nonces.
- Stdio, SSE, stream, multiplex, frame codec, TCP, and shutdown paths reject selected malformed or abusive inputs; sync stdio rejects configured oversized inbound lines before consuming the entire hostile input, configured oversized outbound messages before writing, and outbound writes after shutdown, CLI stdio maps malformed JSON to parse errors and malformed request shapes to invalid-request errors, withholds unregistered capabilities from `initialize`, rejects list/call/read/subscribe/prompt/completion requests before lifecycle completion, denies those requests after lifecycle completion without a negotiated stdio capability grant, and rejects side-effecting notifications instead of silently accepting them, stream chunks reject zero, reserved, and conflicting flag combinations before parsing, stream chunk writes reject over-capacity chunks without advancing sequence numbers or leaving partial buffers and reject writes after terminal chunks without mutating sequence or buffered payload state, SSE endpoint advertisements are not replayed as application messages, SSE event ids sanitize line breaks before rendering to prevent tested field injection, SSE event data and mutated public SSE fields are sanitized at render time to prevent tested carriage-return field injection, SSE live and replay response rendering redacts tested secret-bearing JSON payloads, SSE POST queues enforce tested per-message, count, and aggregate byte caps, reject unknown request/notification methods before queueing, reject tested server-to-client methods and notifications before queueing, reject the legacy `initialized` alias and params on `notifications/initialized` before queueing, validate tested malformed and unsupported-field `notifications/cancelled` params before accepting notification-only POSTs, accept tested notification-only `notifications/initialized` without queueing a response, and do not queue notification-only messages as application responses, SSE replay fails closed when a disabled replay buffer can no longer prove a requested cursor, multiplex outbound frame queues are bounded, pipelined send failures roll back pending request, in-flight, stream, and queued SYN state, locally opened multiplex streams skip control stream id `0` after stream-id wrap, malformed multiplex frames with reserved bytes, unknown flags, conflicting control flags, or payload-bearing stream-control flags are rejected before mutating stream state, unread multiplex receive buffers are bounded and overflow resets the stream instead of leaving it active, close clears queued frames plus active stream state, and TCP refuses to serve plaintext when TLS config is present but TLS accept handling is not wired.
- Security audit receipts, signed server-dispatch denial receipts, structured `LogEntry` JSON/text rendering, `StructuredLogger` stored entries, stored field keys, JSON-RPC errors, SSE endpoint and error events, SSE live rendering, SSE replay and POST queue payloads, stdio transport diagnostics, span names, span/event attributes, Prometheus method labels, CLI stdio debug previews, CLI stdio unknown-method responses, tested oversized, raw secret-bearing, and URL-encoded secret-bearing JSON-RPC id rejection, tested malformed Complete MCP notification handling, and tested legacy/Complete MCP registration-failure receipts redact tested sensitive field names, secret-bearing field keys, single- and double-URL-encoded secret-bearing keys, camelCase secret keys, compact camelCase assignment keys, values, nested generated secret-bearing JSON values, and unstructured `key=value` secret forms; the in-memory security audit log is bounded by default, reports dropped receipt count when capacity is exceeded, caps individual audit text fields at 256 bytes, and sanitizes public mutable event/log fields again at record, render, and emit time.
- Public shutdown request admission and manual in-flight accounting do not increase in-flight work after shutdown has been signaled.

Evidence commands:

```bash
cargo test security -j1 --quiet
cargo test capability -j1 --quiet
cargo test mcp -j1 --quiet
cargo test compat -j1 --quiet
cargo test jsonrpc -j1 --quiet
cargo test protocol -j1 --quiet
cargo test dispatch -j1 --quiet
cargo test -p dcp binary -j1
cargo test -p dcp --test property_tests -j1 binary
cargo test -p dcp --test property_tests -j1 dispatch
cargo test -p dcp --test property_tests -j1 execute_authorized_rejects
cargo test -p dcp --test property_tests -j1 legacy_mcp_adapter_rejects
cargo test transport -j1 --quiet
cargo test stdio -j1 --quiet
cargo test sse -j1 --quiet
cargo test multiplex -j1 --quiet
cargo test shutdown -j1 --quiet
cargo test observability -j1 --quiet
cargo test -p dcp --test property_tests -j1 --quiet security_audit_log_is_bounded_and_counts_dropped_receipts
cargo test -p dcp --test property_tests -j1 --quiet subscription_tracker
cargo test -p dcp --test property_tests -j1 --quiet pipelined_send_failure_rolls_back_pending_and_stream
cargo test -p dcp --test property_tests -j1 --quiet multiplex_receive_buffer_rejects_unread_overflow
cargo test -p dcp --test property_tests -j1 --quiet complete_adapter_rejects_client_originated_elicitation_without_pending_state
cargo test -p dcp --test property_tests -j1 --quiet complete_adapter_rejects_client_originated_roots_and_sampling_after_initialized
cargo test -p dcp --test property_tests -j1 --quiet complete_adapter_initialize_does_not_advertise_client_capabilities_or_false_subscribe
cargo test -p dcp --test property_tests -j1 --quiet complete_adapter_rejects_non_string_protocol_version_without_consuming_initialize
cargo test -p dcp --test property_tests -j1 --quiet complete_adapter_rejects_non_string_cancelled_reason_without_cancelling
cargo test -p dcp --test property_tests -j1 complete_adapter_rejects_extra_cancelled_params_without_cancelling_or_secret_leak
cargo test -p dcp --test property_tests -j1 --quiet sse_post_rejects_server_to_client_methods_before_queue
cargo test -p dcp --test property_tests -j1 --quiet sse_post_rejects_malformed_cancelled_notification_before_queue
cargo test -p dcp --test property_tests -j1 sse_post_rejects_cancelled_notification_extra_params_before_accept
cargo test -p dcp --test property_tests -j1 --quiet uri_template_literal_suffixes_must_match_to_end
cargo test -p dcp --test property_tests -j1 --quiet complete_adapter_rejects_subscribe
cargo test -p dcp --test property_tests -j1 --quiet security_audit_log_sanitizes_mutated_events_on_record
cargo test -p dcp --test property_tests -j1 --quiet security_audit_log_bounds
cargo test -p dcp --test property_tests -j1 --quiet security_redacts_url_encoded_secret_assignments
cargo test -p dcp --test property_tests -j1 --quiet complete_adapter_rejects_url_encoded_secret_bearing_request_id
cargo test -p dcp --test property_tests -j1 --quiet complete_adapter_rejects_legacy_initialized_alias_without_completing_lifecycle
cargo test -p dcp --test property_tests -j1 --quiet complete_adapter_direct_initialized_rejects_request_with_id
cargo test -p dcp --test property_tests -j1 --quiet complete_adapter_rejects_initialized_with_params_without_completing_lifecycle
cargo test -p dcp --test property_tests -j1 --quiet complete_adapter_rejects_remote_shutdown_abuse_with_audit
cargo test -p dcp --test property_tests -j1 --quiet sse_post_rejects_legacy_initialized_notification_alias_before_queue
cargo test -p dcp --test property_tests -j1 --quiet sse_post_rejects_initialized_notification_params_before_queue
cargo test -p dcp --test property_tests -j1 --quiet parser_rejects_null_params_on_requests_and_notifications
cargo test -p dcp -j1 --quiet stdio_tools_list_rejects_before_initialized
cargo test -p dcp -j1 --quiet stdio_initialize_does_not_advertise_unregistered_capabilities
cargo test -p dcp -j1 --quiet stdio_lists_deny_without_negotiated_capability_after_initialized
cargo test -p dcp -j1 --quiet stdio_rejects_side_effecting_notification_methods
cargo test -p dcp --test property_tests -j1 --quiet complete_adapter_authorization_policy_further_restricts_requested_capabilities
cargo test -p dcp --test property_tests -j1 --quiet legacy_mcp_adapter_tools_list_denies_without_negotiated_manifest
cargo test -p dcp --test property_tests -j1 --quiet legacy_mcp_adapter_returns_sanitized_jsonrpc_errors_for_malformed_requests
cargo test -p dcp --test property_tests -j1 --quiet legacy_mcp_adapter_returns_request_too_large_response_without_leaking_payload
cargo test -p dcp --test property_tests -j1 --quiet legacy_mcp_adapter_returns_sanitized_error_for_malformed_tools_call_params
cargo test -p dcp --test property_tests -j1 --quiet legacy_mcp_adapter_direct_initialize_rejects
cargo test -p dcp --test property_tests -j1 --quiet legacy_mcp_adapter_direct_tools_list_rejects
cargo test -p dcp --test property_tests -j1 --quiet legacy_mcp_adapter_direct_tools_call_rejects
cargo test -p dcp --test property_tests -j1 legacy_mcp_adapter_audits
cargo test -p dcp --test property_tests -j1 legacy_mcp_direct_tools_call_audits_missing_params_and_name_without_secret_leak
cargo test -p dcp --test property_tests -j1 legacy_mcp_adapter_rejects_replayed_tool_call_request_id_without_dispatch
cargo test -p dcp --test property_tests -j1 legacy_mcp_adapter_rejects_non_object_meta_before_dispatch
cargo test -p dcp --test property_tests -j1 complete_adapter_tools_call_rejects_non_object_meta_before_dispatch
cargo test -p dcp --test property_tests -j1 complete_adapter_tools_call_rejects_replayed_request_id_without_dispatch
cargo test -p dcp --test property_tests -j1 complete_adapter_rejects_unknown_top_level_jsonrpc_fields_without_dispatch
cargo test -p dcp --test property_tests -j1 --quiet sse_post_rejects_when_pending_queue_byte_budget_is_full
cargo test -p dcp --test property_tests -j1 --quiet sse_event_id_cannot_inject_fields_with_crlf
cargo test -p dcp --test property_tests -j1 --quiet security_redacts_double_url_encoded_secret_assignments
cargo test -p dcp --test property_tests -j1 --quiet sse_event_data_cannot_inject_fields_with_cr
cargo test -p dcp --test property_tests -j1 --quiet sse_event_format_sanitizes_public_field_mutation
cargo test -p dcp --test property_tests -j1 --quiet sse_live_and_replay_redact_secret_bearing_response_payloads
cargo test -p dcp --test property_tests -j1 --quiet prop_stream_chunk_rejects_malformed_flags
cargo test -p dcp --test property_tests -j1 --quiet parser_rejects_control_character_method_names
cargo test -p dcp --test property_tests -j1 --quiet parser_format_response_rejects_invalid_response_shapes
cargo test -p dcp --test property_tests -j1 --quiet complete_adapter_list_methods_reject_malformed_params
cargo test -p dcp --test property_tests -j1 --quiet complete_adapter_direct_handlers_reject_request_notification_mismatch
cargo test -p dcp --test property_tests -j1 --quiet complete_adapter_direct_initialize_requires_initialize_method
cargo test -p dcp --test property_tests -j1 --quiet prop_version_negotiation_strict_rejects_unsupported
cargo test -p dcp --test property_tests -j1 --quiet complete_adapter_rejects_unsupported_protocol_version_without_consuming_initialize
cargo test -p dcp --test property_tests -j1 --quiet test_log_entry_rendering_and_emit_sanitize_public_mutation
cargo test -p dcp --test property_tests -j1 --quiet observability
cargo test -p dcp --test property_tests -j1 --quiet mcp2025
cargo test -p dcp --test property_tests -j1 --quiet mcp
cargo test -p dcp --test property_tests -j1 --quiet execute_signed_authorized
cargo test -p dcp --test property_tests -j1 --quiet test_server_invoke_signed_authorized
cargo test -p dcp --test property_tests -j1 test_raw_server_invoke_denials_record_sanitized_security_audit_receipts
cargo test -p dcp --test property_tests -j1 --quiet dispatch
cargo test -p dcp --test property_tests -j1 --quiet server
cargo test -p dcp --test property_tests -j1 --quiet security
cargo test -p dcp security -j1 --quiet
cargo test -p dcp --test property_tests -j1 --quiet multiplex_rejects_reserved_and_unknown_flag_bits
cargo test -p dcp --test property_tests -j1 --quiet multiplex_rejects_payload_bearing_stream_control_frames
cargo test -p dcp --test property_tests -j1 --quiet multiplex_rejects_conflicting_stream_control_flags
cargo test -p dcp -j1 --quiet open_stream_wrap_skips_control_stream
cargo test -p dcp --test property_tests complete_adapter_tools_call -j1
cargo test -p dcp --test property_tests parser_rejects_unknown_jsonrpc -j1
cargo test -p dcp --test property_tests parser_rejects -j1
cargo test -p dcp --test property_tests prop_message_parsing_correctness -j1
```

Remaining unproven areas include mandatory inbound signature verification on every execution path, full stdio CLI parity for registered negotiated capability wiring and structured audit receipts, resource/prompt/server/SDK coverage for server-side authorization policy, SDK DCP capability negotiation parity, SDK server-to-client role parity, actual TCP TLS acceptor/handshake enforcement, adapter-per-client session isolation, cross-session/domain-scoped request and SSE replay isolation, signed nonce domain scoping, bounded async stdio reads, tracked TCP task/socket cancellation on shutdown, legacy adapter JSON-RPC notification no-response compatibility, Complete direct handler capability-denial audit parity, broader SDK redaction parity, and multiplex sequence/generation replay protection.


## Project Structure


@tree:src[]


## License


MIT License - see LICENSE (LICENSE) for details.


## Contributing


Contributions welcome! Please read our contributing guidelines and submit PRs. -Fork the repository -Create a feature branch -Add tests for new functionality -Ensure all tests pass: `cargo test --release` -Run clippy: `cargo clippy` -Submit a pull request
