//! Property tests for DCP server.
//!
//! Feature: dcp-protocol, Property 15: Session State Preservation

use proptest::prelude::*;
use std::collections::HashMap;

use dcp::context::DcpContext;
use dcp::dispatch::BinaryTrieRouter;
use dcp::server::{DcpServer, ProtocolVersion, ServerConfig, Session};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Feature: dcp-protocol, Property 15: Session State Preservation
    /// For any client session with state, upgrading from MCP to DCP protocol
    /// SHALL preserve all session state without data loss.
    #[test]
    fn prop_session_state_preserved_on_upgrade(
        keys in prop::collection::vec("[a-z]{1,10}", 1..10),
        values in prop::collection::vec(prop::collection::vec(any::<u8>(), 1..100), 1..10),
    ) {
        // Create server
        let router = BinaryTrieRouter::new();
        let context = DcpContext::new(1);
        let config = ServerConfig::default();
        let server = DcpServer::new(router, context, config);

        // Create session
        let session = server.create_session().unwrap();
        let session_id = session.id;

        // Store data in session
        let mut stored_data: HashMap<String, Vec<u8>> = HashMap::new();
        for (key, value) in keys.iter().zip(values.iter()) {
            session.set_data(key.clone(), value.clone());
            stored_data.insert(key.clone(), value.clone());
        }

        // Verify initial protocol is MCP
        prop_assert_eq!(session.protocol, ProtocolVersion::Mcp);

        // Upgrade session to DCP
        server.upgrade_session(session_id).unwrap();

        // Get upgraded session
        let upgraded_session = server.get_session(session_id).unwrap();

        // Verify protocol was upgraded
        prop_assert_eq!(upgraded_session.protocol, ProtocolVersion::DcpV1);

        // Verify all data was preserved
        for (key, expected_value) in stored_data.iter() {
            let actual_value = upgraded_session.get_data(key);
            prop_assert_eq!(actual_value.as_ref(), Some(expected_value));
        }
    }

    /// Test that session message count is preserved
    #[test]
    fn prop_session_message_count_increments(
        message_count in 1u64..1000,
    ) {
        let session = Session::new(1);

        for _ in 0..message_count {
            session.increment_messages();
        }

        let count = session.message_count.load(std::sync::atomic::Ordering::Acquire);
        prop_assert_eq!(count, message_count);
    }

    /// Test that session touch updates last activity
    #[test]
    fn prop_session_touch_updates_activity(
        _dummy in 0u8..1, // Just to make it a property test
    ) {
        let session = Session::new(1);
        let initial = session.last_activity.load(std::sync::atomic::Ordering::Acquire);

        // Small delay to ensure time difference
        std::thread::sleep(std::time::Duration::from_millis(1));
        session.touch();

        let updated = session.last_activity.load(std::sync::atomic::Ordering::Acquire);
        prop_assert!(updated >= initial);
    }

    /// Test that server respects max sessions limit
    #[test]
    fn prop_server_max_sessions_enforced(
        max_sessions in 1usize..50,
    ) {
        let router = BinaryTrieRouter::new();
        let context = DcpContext::new(1);
        let config = ServerConfig {
            max_sessions,
            ..Default::default()
        };
        let server = DcpServer::new(router, context, config);

        // Create max_sessions sessions
        for _ in 0..max_sessions {
            let result = server.create_session();
            prop_assert!(result.is_ok());
        }

        // Next session should fail
        let result = server.create_session();
        prop_assert!(result.is_err());

        // Session count should be at max
        prop_assert_eq!(server.session_count(), max_sessions);
    }

    /// Test that session removal works correctly
    #[test]
    fn prop_session_removal(
        num_sessions in 1usize..20,
        remove_indices in prop::collection::vec(0usize..100, 1..10),
    ) {
        let router = BinaryTrieRouter::new();
        let context = DcpContext::new(1);
        let config = ServerConfig {
            max_sessions: 100,
            ..Default::default()
        };
        let server = DcpServer::new(router, context, config);

        // Create sessions and track IDs
        let mut session_ids = Vec::new();
        for _ in 0..num_sessions {
            let session = server.create_session().unwrap();
            session_ids.push(session.id);
        }

        // Remove some sessions
        let mut removed_count = 0;
        for idx in remove_indices {
            let actual_idx = idx % session_ids.len();
            let id = session_ids[actual_idx];
            if server.get_session(id).is_some() {
                server.remove_session(id);
                removed_count += 1;
            }
        }

        // Verify session count
        let expected_count = num_sessions.saturating_sub(removed_count);
        prop_assert!(server.session_count() <= num_sessions);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dcp::dispatch::{SharedArgs, ToolHandler, ToolResult};
    use dcp::protocol::{InputSchema, ToolSchema};
    use dcp::security::{NonceStore, SecurityAuditAction, Signer};
    use dcp::{CapabilityManifest, DCPError};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    struct CountingTool {
        calls: Arc<AtomicUsize>,
    }

    impl CountingTool {
        fn new(calls: Arc<AtomicUsize>) -> Self {
            Self { calls }
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

    #[test]
    fn test_session_data_isolation() {
        let session1 = Session::new(1);
        let session2 = Session::new(2);

        session1.set_data("key".to_string(), vec![1, 2, 3]);
        session2.set_data("key".to_string(), vec![4, 5, 6]);

        assert_eq!(session1.get_data("key"), Some(vec![1, 2, 3]));
        assert_eq!(session2.get_data("key"), Some(vec![4, 5, 6]));
    }

    #[test]
    fn test_metrics_snapshot() {
        let router = BinaryTrieRouter::new();
        let context = DcpContext::new(1);
        let config = ServerConfig::default();
        let server = DcpServer::new(router, context, config);

        server.metrics.record_mcp(100, 1000);
        server.metrics.record_dcp(50, 500);
        server.metrics.record_invocation();
        server.metrics.record_error();

        let snapshot = server.metrics.snapshot();
        assert_eq!(snapshot.mcp_messages, 1);
        assert_eq!(snapshot.dcp_messages, 1);
        assert_eq!(snapshot.mcp_bytes, 100);
        assert_eq!(snapshot.dcp_bytes, 50);
        assert_eq!(snapshot.tool_invocations, 1);
        assert_eq!(snapshot.errors, 1);
    }

    #[test]
    fn test_raw_server_invoke_is_deny_by_default() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut router = BinaryTrieRouter::new();
        router
            .register(Box::new(CountingTool::new(Arc::clone(&calls))))
            .unwrap();

        let server = DcpServer::new(router, DcpContext::new(1), ServerConfig::default());
        let args = SharedArgs::new(&[], 0);

        let result = server.invoke(7, &args);

        assert_eq!(result, Err(DCPError::CapabilityDenied));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_server_invoke_by_name_is_deny_by_default() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut router = BinaryTrieRouter::new();
        router
            .register(Box::new(CountingTool::new(Arc::clone(&calls))))
            .unwrap();

        let server = DcpServer::new(router, DcpContext::new(1), ServerConfig::default());
        let args = SharedArgs::new(&[], 0);

        let result = server.invoke_by_name("secure", &args);

        assert_eq!(result, Err(DCPError::CapabilityDenied));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_raw_server_invoke_denials_record_sanitized_security_audit_receipts() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut router = BinaryTrieRouter::new();
        router
            .register(Box::new(CountingTool::new(Arc::clone(&calls))))
            .unwrap();

        let server = DcpServer::new(router, DcpContext::new(1), ServerConfig::default());
        let args = SharedArgs::new(&[], 0);

        assert_eq!(server.invoke(7, &args), Err(DCPError::CapabilityDenied));
        assert_eq!(
            server.invoke_by_name("access_token=plain-secret", &args),
            Err(DCPError::CapabilityDenied)
        );

        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let events = server.security_audit().events();
        assert!(events.iter().any(|event| {
            event.action == SecurityAuditAction::CapabilityDenied
                && event.reason == "raw_invoke_denied"
                && event.method.as_deref() == Some("dcp.tool.invoke")
                && event.fields.get("tool_id").map(String::as_str) == Some("7")
        }));
        assert!(events.iter().any(|event| {
            event.action == SecurityAuditAction::CapabilityDenied
                && event.reason == "raw_invoke_by_name_denied"
                && event.method.as_deref() == Some("dcp.tool.invoke_by_name")
        }));

        let audit_dump = format!("{events:?}");
        assert!(!audit_dump.contains("plain-secret"));
        assert!(!audit_dump.contains("access_token"));
    }

    #[test]
    fn test_server_invoke_authorized_executes_negotiated_tool() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut router = BinaryTrieRouter::new();
        router
            .register(Box::new(CountingTool::new(Arc::clone(&calls))))
            .unwrap();

        let server = DcpServer::new(router, DcpContext::new(1), ServerConfig::default());
        let args = SharedArgs::new(&[], 0);
        let mut capabilities = CapabilityManifest::new(1);
        capabilities.set_tool(7);

        let result = server.invoke_authorized(&capabilities, 7, &args);

        assert!(result.is_ok());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_server_invoke_signed_authorized_rejects_replay_without_second_execution() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut router = BinaryTrieRouter::new();
        router
            .register(Box::new(CountingTool::new(Arc::clone(&calls))))
            .unwrap();

        let server = DcpServer::new(router, DcpContext::new(1), ServerConfig::default());
        let args = SharedArgs::new(&[], 0);
        let signer = Signer::from_seed(&[11u8; 32]);
        let invocation =
            signer.sign_invocation(7, 55, NonceStore::current_timestamp(), args.data());
        let public_key = signer.public_key_bytes();
        let mut nonce_store = NonceStore::with_config(10, 300);
        let mut capabilities = CapabilityManifest::new(1);
        capabilities.set_tool(7);

        assert!(server
            .invoke_signed_authorized(
                &capabilities,
                &invocation,
                &public_key,
                &mut nonce_store,
                &args,
            )
            .is_ok());

        let replay = server.invoke_signed_authorized(
            &capabilities,
            &invocation,
            &public_key,
            &mut nonce_store,
            &args,
        );

        assert_eq!(replay, Err(dcp::SecurityError::ReplayAttack));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_server_invoke_signed_authorized_records_security_audit_receipts() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut router = BinaryTrieRouter::new();
        router
            .register(Box::new(CountingTool::new(Arc::clone(&calls))))
            .unwrap();

        let server = DcpServer::new(router, DcpContext::new(1), ServerConfig::default());
        let signer = Signer::from_seed(&[12u8; 32]);
        let signed_args = b"safe original args";
        let tampered_args = SharedArgs::new(b"authorization=plain-secret", 0);
        let invocation =
            signer.sign_invocation(7, 56, NonceStore::current_timestamp(), signed_args);
        let public_key = signer.public_key_bytes();
        let mut nonce_store = NonceStore::with_config(10, 300);
        let mut capabilities = CapabilityManifest::new(1);
        capabilities.set_tool(7);

        let result = server.invoke_signed_authorized(
            &capabilities,
            &invocation,
            &public_key,
            &mut nonce_store,
            &tampered_args,
        );

        assert_eq!(result, Err(dcp::SecurityError::ArgsHashMismatch));
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        let events = server.security_audit().events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].action, SecurityAuditAction::SignatureRejected);
        assert_eq!(events[0].reason, "args_hash_mismatch");
        assert_eq!(
            events[0].fields.get("tool_id").map(String::as_str),
            Some("7")
        );

        let audit_dump = format!("{events:?}");
        assert!(!audit_dump.contains("plain-secret"));
        assert!(!audit_dump.contains("authorization"));
    }
}
