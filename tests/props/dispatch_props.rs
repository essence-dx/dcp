//! Property-based tests for dispatch layer.
//!
//! Feature: dcp-protocol, Property 6: Tool Dispatch Correctness

use dcp::binary::ArgType;
use dcp::capability::CapabilityManifest;
use dcp::dispatch::{BinaryTrieRouter, SharedArgs, ToolHandler, ToolResult};
use dcp::protocol::schema::{FieldDef, InputSchema, ToolSchema};
use dcp::security::{NonceStore, Signer};
use dcp::{DCPError, SecurityError};
use proptest::prelude::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

// Test handler implementation for property tests
struct PropTestHandler {
    schema: ToolSchema,
}

#[cfg(test)]
mod security_tests {
    use super::*;

    struct CountingHandler {
        schema: ToolSchema,
        calls: Arc<AtomicUsize>,
    }

    struct NoArgCountingHandler {
        schema: ToolSchema,
        calls: Arc<AtomicUsize>,
    }

    impl CountingHandler {
        fn new(calls: Arc<AtomicUsize>) -> Self {
            let mut input = InputSchema::new();
            input.add_field(FieldDef::new("enabled", ArgType::Bool, 0, 1));
            input.set_required(0);

            Self {
                schema: ToolSchema {
                    name: "secure_tool",
                    id: 7,
                    description: "requires validated args",
                    input,
                },
                calls,
            }
        }
    }

    impl NoArgCountingHandler {
        fn new(calls: Arc<AtomicUsize>) -> Self {
            Self {
                schema: ToolSchema {
                    name: "raw_tool",
                    id: 9,
                    description: "must not run without capabilities",
                    input: InputSchema::new(),
                },
                calls,
            }
        }
    }

    impl ToolHandler for CountingHandler {
        fn execute(&self, _args: &SharedArgs) -> Result<ToolResult, DCPError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(ToolResult::empty())
        }

        fn schema(&self) -> &ToolSchema {
            &self.schema
        }
    }

    impl ToolHandler for NoArgCountingHandler {
        fn execute(&self, _args: &SharedArgs) -> Result<ToolResult, DCPError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(ToolResult::empty())
        }

        fn schema(&self) -> &ToolSchema {
            &self.schema
        }
    }

    #[test]
    fn public_execute_is_deny_by_default_without_capability() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut router = BinaryTrieRouter::new();
        router
            .register(Box::new(NoArgCountingHandler::new(Arc::clone(&calls))))
            .unwrap();

        let args = SharedArgs::new(&[], 0);
        let result = router.execute(9, &args);

        assert_eq!(result, Err(DCPError::CapabilityDenied));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn public_execute_denies_before_schema_validation_or_handler_execution() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut router = BinaryTrieRouter::new();
        router
            .register(Box::new(CountingHandler::new(Arc::clone(&calls))))
            .unwrap();

        let args = SharedArgs::new(&[1], 0);
        let result = router.execute(7, &args);

        assert_eq!(result, Err(DCPError::CapabilityDenied));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn execute_authorized_reports_validation_without_running_handler() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut router = BinaryTrieRouter::new();
        router
            .register(Box::new(CountingHandler::new(Arc::clone(&calls))))
            .unwrap();

        let mut capabilities = CapabilityManifest::new(1);
        capabilities.set_tool(7);

        let args = SharedArgs::new(&[1], 0);
        let result = router.execute_authorized(&capabilities, 7, &args);

        assert_eq!(result, Err(SecurityError::ValidationFailed));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn execute_authorized_rejects_nonempty_raw_args_for_empty_schema() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut router = BinaryTrieRouter::new();
        router
            .register(Box::new(NoArgCountingHandler::new(Arc::clone(&calls))))
            .unwrap();

        let mut capabilities = CapabilityManifest::new(1);
        capabilities.set_tool(9);

        let args = SharedArgs::new(b"api_key=plain-secret", 0);
        let result = router.execute_authorized(&capabilities, 9, &args);

        assert_eq!(result, Err(SecurityError::ValidationFailed));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn execute_authorized_rejects_trailing_bytes_beyond_declared_schema() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut router = BinaryTrieRouter::new();
        router
            .register(Box::new(CountingHandler::new(Arc::clone(&calls))))
            .unwrap();

        let mut capabilities = CapabilityManifest::new(1);
        capabilities.set_tool(7);

        let args = SharedArgs::new(b"\x01api_key=plain-secret", ArgType::Bool as u64);
        let result = router.execute_authorized(&capabilities, 7, &args);

        assert_eq!(result, Err(SecurityError::ValidationFailed));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn binary_trie_router_rejects_tool_registration_outside_capacity() {
        let mut router = BinaryTrieRouter::new();
        let overflow_id = BinaryTrieRouter::MAX_TOOLS as u16;

        let result = router.register(Box::new(PropTestHandler::new(
            overflow_id,
            "overflow".to_string(),
        )));

        assert_eq!(result, Err(DCPError::ValidationFailed));
        assert_eq!(router.tool_count(), 0);
        assert_eq!(router.resolve_name("overflow"), None);
    }

    #[test]
    fn binary_trie_router_rejects_duplicate_tool_names_and_ids() {
        let mut router = BinaryTrieRouter::new();

        let tool_id = router
            .register(Box::new(PropTestHandler::new(7, "visible".to_string())))
            .unwrap();
        let duplicate_name =
            router.register(Box::new(PropTestHandler::new(8, "visible".to_string())));
        let duplicate_id = router.register(Box::new(PropTestHandler::new(7, "hidden".to_string())));

        assert_eq!(tool_id, 7);
        assert_eq!(duplicate_name, Err(DCPError::ValidationFailed));
        assert_eq!(duplicate_id, Err(DCPError::ValidationFailed));
        assert_eq!(router.tool_count(), 1);
        assert_eq!(router.max_tool_id(), 7);
        assert_eq!(router.resolve_name("visible"), Some(7));
        assert_eq!(router.resolve_name("hidden"), None);
        assert!(router.has_tool(7));
        assert!(!router.has_tool(8));
    }

    #[test]
    fn execute_signed_authorized_runs_handler_after_signature_capability_and_nonce_checks() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut router = BinaryTrieRouter::new();
        router
            .register(Box::new(NoArgCountingHandler::new(Arc::clone(&calls))))
            .unwrap();

        let signer = Signer::from_seed(&[7u8; 32]);
        let args = SharedArgs::new(&[], 0);
        let now = NonceStore::current_timestamp();
        let invocation = signer.sign_invocation(9, 1, now, args.data());
        let public_key = signer.public_key_bytes();
        let mut nonce_store = NonceStore::with_config(10, 300);
        let mut capabilities = CapabilityManifest::new(1);
        capabilities.set_tool(9);

        let result = router.execute_signed_authorized(
            &capabilities,
            &invocation,
            &public_key,
            &mut nonce_store,
            &args,
        );

        assert!(matches!(result, Ok(result) if result.is_success()));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(nonce_store.len(), 1);
    }

    #[test]
    fn execute_signed_authorized_rejects_args_hash_mismatch_without_running_handler() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut router = BinaryTrieRouter::new();
        router
            .register(Box::new(NoArgCountingHandler::new(Arc::clone(&calls))))
            .unwrap();

        let signer = Signer::from_seed(&[8u8; 32]);
        let signed_args = b"safe original args";
        let tampered_args = SharedArgs::new(b"mutated args", 0);
        let now = NonceStore::current_timestamp();
        let invocation = signer.sign_invocation(9, 2, now, signed_args);
        let public_key = signer.public_key_bytes();
        let mut nonce_store = NonceStore::with_config(10, 300);
        let mut capabilities = CapabilityManifest::new(1);
        capabilities.set_tool(9);

        let result = router.execute_signed_authorized(
            &capabilities,
            &invocation,
            &public_key,
            &mut nonce_store,
            &tampered_args,
        );

        assert_eq!(result, Err(SecurityError::ArgsHashMismatch));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(nonce_store.len(), 0);
    }

    #[test]
    fn execute_signed_authorized_rejects_replayed_nonce_without_running_handler_again() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut router = BinaryTrieRouter::new();
        router
            .register(Box::new(NoArgCountingHandler::new(Arc::clone(&calls))))
            .unwrap();

        let signer = Signer::from_seed(&[9u8; 32]);
        let args = SharedArgs::new(&[], 0);
        let now = NonceStore::current_timestamp();
        let invocation = signer.sign_invocation(9, 3, now, args.data());
        let public_key = signer.public_key_bytes();
        let mut nonce_store = NonceStore::with_config(10, 300);
        let mut capabilities = CapabilityManifest::new(1);
        capabilities.set_tool(9);

        assert!(router
            .execute_signed_authorized(
                &capabilities,
                &invocation,
                &public_key,
                &mut nonce_store,
                &args,
            )
            .is_ok());

        let replay = router.execute_signed_authorized(
            &capabilities,
            &invocation,
            &public_key,
            &mut nonce_store,
            &args,
        );

        assert_eq!(replay, Err(SecurityError::ReplayAttack));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(nonce_store.len(), 1);
    }

    #[test]
    fn execute_signed_authorized_rejects_missing_capability_and_blocks_later_replay() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut router = BinaryTrieRouter::new();
        router
            .register(Box::new(NoArgCountingHandler::new(Arc::clone(&calls))))
            .unwrap();

        let signer = Signer::from_seed(&[10u8; 32]);
        let args = SharedArgs::new(&[], 0);
        let now = NonceStore::current_timestamp();
        let invocation = signer.sign_invocation(9, 4, now, args.data());
        let public_key = signer.public_key_bytes();
        let mut nonce_store = NonceStore::with_config(10, 300);
        let capabilities = CapabilityManifest::new(1);

        let result = router.execute_signed_authorized(
            &capabilities,
            &invocation,
            &public_key,
            &mut nonce_store,
            &args,
        );

        assert_eq!(result, Err(SecurityError::InsufficientCapabilities));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(nonce_store.len(), 1);

        let mut elevated_capabilities = CapabilityManifest::new(1);
        elevated_capabilities.set_tool(9);
        let replay = router.execute_signed_authorized(
            &elevated_capabilities,
            &invocation,
            &public_key,
            &mut nonce_store,
            &args,
        );

        assert_eq!(replay, Err(SecurityError::ReplayAttack));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}

impl PropTestHandler {
    fn new(id: u16, name: String) -> Self {
        // Leak the string to get a 'static lifetime (acceptable in tests)
        let name: &'static str = Box::leak(name.into_boxed_str());
        Self {
            schema: ToolSchema {
                name,
                id,
                description: "Property test tool",
                input: InputSchema::new(),
            },
        }
    }
}

impl ToolHandler for PropTestHandler {
    fn execute(&self, _args: &SharedArgs) -> Result<ToolResult, DCPError> {
        // Return the tool ID as the result for verification
        Ok(ToolResult::success(self.schema.id.to_le_bytes().to_vec()))
    }

    fn schema(&self) -> &ToolSchema {
        &self.schema
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Feature: dcp-protocol, Property 6: Tool Dispatch Correctness
    /// For any valid tool_id in range [0, max_registered_id], the Binary_Trie_Router
    /// SHALL dispatch to the correct handler.
    /// **Validates: Requirements 4.2, 4.3**
    #[test]
    fn prop_dispatch_valid_tool_id(
        tool_ids in prop::collection::vec(0u16..1000, 1..20),
    ) {
        let mut router = BinaryTrieRouter::new();

        // Register all tools
        for &id in &tool_ids {
            let name = format!("tool_{}", id);
            let handler = Box::new(PropTestHandler::new(id, name));
            let _ = router.register(handler); // Ignore duplicate registrations
        }

        // Verify public schema lookup returns the correct registered tool without exposing handlers.
        for &id in &tool_ids {
            if let Some(schema) = router.tool_schema(id) {
                prop_assert_eq!(schema.id, id);
            }
        }
    }

    /// Feature: dcp-protocol, Property 6: Tool Dispatch Correctness
    /// For any invalid tool_id, the Binary_Trie_Router SHALL return an error
    /// without panicking.
    /// **Validates: Requirements 4.5**
    #[test]
    fn prop_dispatch_invalid_tool_id(
        registered_ids in prop::collection::vec(0u16..100, 1..10),
        query_id in 0u16..1000,
    ) {
        let mut router = BinaryTrieRouter::new();

        // Register some tools
        for &id in &registered_ids {
            let name = format!("tool_{}", id);
            let handler = Box::new(PropTestHandler::new(id, name));
            let _ = router.register(handler);
        }

        // Query should not panic and should not expose executable handlers.
        let result = router.tool_schema(query_id);

        // If query_id is in registered_ids, should find handler
        // Otherwise, should return None
        if registered_ids.contains(&query_id) {
            prop_assert!(result.is_some());
            prop_assert_eq!(result.unwrap().id, query_id);
        } else {
            prop_assert!(result.is_none());
        }
    }

    /// Feature: dcp-protocol, Property 6: Tool Dispatch Correctness
    /// Raw execute on invalid tool_id SHALL deny without revealing existence.
    /// **Validates: Requirements 4.5**
    #[test]
    fn prop_raw_execute_invalid_denies_without_revealing_existence(
        registered_ids in prop::collection::vec(0u16..50, 0..5),
        query_id in 100u16..200, // Always outside registered range
    ) {
        let mut router = BinaryTrieRouter::new();

        for &id in &registered_ids {
            let name = format!("tool_{}", id);
            let handler = Box::new(PropTestHandler::new(id, name));
            let _ = router.register(handler);
        }

        let args = SharedArgs::new(&[], 0);
        let result = router.execute(query_id, &args);

        prop_assert_eq!(result, Err(DCPError::CapabilityDenied));
    }

    /// Feature: dcp-protocol, Property 6: Tool Dispatch Correctness
    /// Name resolution SHALL return correct tool_id for registered tools.
    /// **Validates: Requirements 4.3**
    #[test]
    fn prop_name_resolution(
        tool_ids in prop::collection::vec(0u16..500, 1..15),
    ) {
        let mut router = BinaryTrieRouter::new();

        // Register tools and track names
        let mut registered: Vec<(u16, String)> = Vec::new();
        for &id in &tool_ids {
            let name = format!("tool_{}", id);
            let handler = Box::new(PropTestHandler::new(id, name.clone()));
            if router.register(handler).is_ok() {
                registered.push((id, name));
            }
        }

        // Verify name resolution
        for (id, name) in &registered {
            let resolved = router.resolve_name(name);
            prop_assert_eq!(resolved, Some(*id));
        }

        // Unknown names should return None
        prop_assert_eq!(router.resolve_name("unknown_tool"), None);
    }

    /// Feature: dcp-protocol, Property 6: Tool Dispatch Correctness
    /// Authorized execute on valid tool_id SHALL return correct result.
    /// **Validates: Requirements 4.2**
    #[test]
    fn prop_execute_authorized_valid_returns_result(
        tool_id in 0u16..100,
    ) {
        let mut router = BinaryTrieRouter::new();

        let name = format!("tool_{}", tool_id);
        let handler = Box::new(PropTestHandler::new(tool_id, name));
        router.register(handler).unwrap();

        let args = SharedArgs::new(&[], 0);
        let mut capabilities = CapabilityManifest::new(1);
        capabilities.set_tool(tool_id);
        let result = router.execute_authorized(&capabilities, tool_id, &args).unwrap();

        prop_assert!(result.is_success());
        // Verify the result contains the tool_id
        let payload = result.payload().unwrap();
        let returned_id = u16::from_le_bytes([payload[0], payload[1]]);
        prop_assert_eq!(returned_id, tool_id);
    }
}
