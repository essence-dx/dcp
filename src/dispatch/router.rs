//! Binary Trie Router for O(1) tool dispatch.

use std::collections::HashMap;

use crate::binary::SignedInvocation;
use crate::dispatch::handler::{SharedArgs, ToolHandler, ToolResult};
use crate::protocol::schema::SchemaValidator;
use crate::protocol::ToolSchema;
use crate::security::{NonceStore, Verifier};
use crate::{CapabilityManifest, DCPError, SecurityError};

/// Compile-time generated tool router with O(1) dispatch
pub struct BinaryTrieRouter {
    /// Direct dispatch table - tool_id is array index
    handlers: Vec<Option<Box<dyn ToolHandler>>>,
    /// Tool name to ID mapping (for MCP compatibility)
    name_to_id: HashMap<String, u16>,
    /// Maximum registered tool ID
    max_tool_id: u16,
}

impl BinaryTrieRouter {
    /// Maximum number of tools supported
    pub const MAX_TOOLS: usize = CapabilityManifest::MAX_TOOLS;

    /// Create a new empty router
    pub fn new() -> Self {
        Self {
            handlers: Vec::new(),
            name_to_id: HashMap::new(),
            max_tool_id: 0,
        }
    }

    /// Create a router with pre-allocated capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            handlers: Vec::with_capacity(capacity.min(Self::MAX_TOOLS)),
            name_to_id: HashMap::with_capacity(capacity),
            max_tool_id: 0,
        }
    }

    /// Register a tool handler
    pub fn register(&mut self, handler: Box<dyn ToolHandler>) -> Result<u16, DCPError> {
        let tool_id = handler.tool_id();
        let tool_name = handler.tool_name().to_string();

        // Ensure handlers vec is large enough
        let id_usize = tool_id as usize;
        if id_usize >= Self::MAX_TOOLS {
            return Err(DCPError::ValidationFailed);
        }
        if self.name_to_id.contains_key(&tool_name) {
            return Err(DCPError::ValidationFailed);
        }
        if self
            .handlers
            .get(id_usize)
            .and_then(|handler| handler.as_ref())
            .is_some()
        {
            return Err(DCPError::ValidationFailed);
        }

        while self.handlers.len() <= id_usize {
            self.handlers.push(None);
        }

        // Register the handler
        self.handlers[id_usize] = Some(handler);
        self.name_to_id.insert(tool_name, tool_id);

        if tool_id > self.max_tool_id {
            self.max_tool_id = tool_id;
        }

        Ok(tool_id)
    }

    /// O(1) internal dispatch by tool ID.
    #[inline(always)]
    pub(crate) fn dispatch(&self, tool_id: u16) -> Option<&dyn ToolHandler> {
        self.handlers
            .get(tool_id as usize)
            .and_then(|h| h.as_ref())
            .map(|h| h.as_ref())
    }

    /// Get the registered schema for a tool ID.
    pub fn tool_schema(&self, tool_id: u16) -> Option<&ToolSchema> {
        self.dispatch(tool_id).map(|handler| handler.schema())
    }

    /// Raw tool execution is deny-by-default.
    ///
    /// Runtime callers must use `execute_authorized` with a negotiated
    /// capability manifest so tool execution cannot bypass authorization.
    pub fn execute(&self, tool_id: u16, args: &SharedArgs) -> Result<ToolResult, DCPError> {
        let _ = (tool_id, args);
        Err(DCPError::CapabilityDenied)
    }

    /// Execute a tool only if it is present in the negotiated capability set.
    pub fn execute_authorized(
        &self,
        capabilities: &CapabilityManifest,
        tool_id: u16,
        args: &SharedArgs,
    ) -> Result<ToolResult, SecurityError> {
        let handler = self.validate_authorized_tool(capabilities, tool_id, args)?;
        handler
            .execute(args)
            .map_err(|_| SecurityError::InsufficientCapabilities)
    }

    /// Execute a signed invocation only after signature, args hash,
    /// negotiated capability, schema, and replay checks all pass.
    pub fn execute_signed_authorized(
        &self,
        capabilities: &CapabilityManifest,
        invocation: &SignedInvocation,
        public_key: &[u8; 32],
        nonce_store: &mut NonceStore,
        args: &SharedArgs,
    ) -> Result<ToolResult, SecurityError> {
        Verifier::verify_invocation(invocation, public_key)?;
        if !Verifier::verify_args_hash(invocation, args.data()) {
            return Err(SecurityError::ArgsHashMismatch);
        }

        let tool_id = u16::try_from(invocation.tool_id)
            .map_err(|_| SecurityError::InsufficientCapabilities)?;
        nonce_store.check_nonce(invocation.nonce, invocation.timestamp)?;

        let handler = self.validate_authorized_tool(capabilities, tool_id, args)?;

        handler
            .execute(args)
            .map_err(|_| SecurityError::InsufficientCapabilities)
    }

    fn validate_authorized_tool(
        &self,
        capabilities: &CapabilityManifest,
        tool_id: u16,
        args: &SharedArgs,
    ) -> Result<&dyn ToolHandler, SecurityError> {
        capabilities.require_tool(tool_id)?;
        let handler = self
            .dispatch(tool_id)
            .ok_or(SecurityError::InsufficientCapabilities)?;
        SchemaValidator::validate_shared_args(&handler.schema().input, args)
            .map_err(|_| SecurityError::ValidationFailed)?;
        Ok(handler)
    }

    /// Resolve tool name to ID (for MCP compatibility)
    pub fn resolve_name(&self, name: &str) -> Option<u16> {
        self.name_to_id.get(name).copied()
    }

    /// Get the maximum registered tool ID
    pub fn max_tool_id(&self) -> u16 {
        self.max_tool_id
    }

    /// Get the number of registered tools
    pub fn tool_count(&self) -> usize {
        self.handlers.iter().filter(|h| h.is_some()).count()
    }

    /// Check if a tool ID is registered
    pub fn has_tool(&self, tool_id: u16) -> bool {
        self.dispatch(tool_id).is_some()
    }

    /// Get all registered tool names
    pub fn tool_names(&self) -> impl Iterator<Item = &str> {
        self.name_to_id.keys().map(|s| s.as_str())
    }

    /// Get server capabilities based on registered tools
    pub fn capabilities(&self) -> ServerCapabilities {
        ServerCapabilities {
            tools: self.tool_count() > 0,
            resources: false, // TODO: implement resource handlers
            prompts: false,   // TODO: implement prompt handlers
            logging: true,
        }
    }
}

/// Server capabilities
#[derive(Debug, Clone, Default)]
pub struct ServerCapabilities {
    pub tools: bool,
    pub resources: bool,
    pub prompts: bool,
    pub logging: bool,
}

impl Default for BinaryTrieRouter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::schema::{InputSchema, ToolSchema};

    // Test handler implementation
    struct TestHandler {
        schema: ToolSchema,
    }

    impl TestHandler {
        fn new(id: u16, name: &'static str) -> Self {
            Self {
                schema: ToolSchema {
                    name,
                    id,
                    description: "Test tool",
                    input: InputSchema::new(),
                },
            }
        }
    }

    impl ToolHandler for TestHandler {
        fn execute(&self, _args: &SharedArgs) -> Result<ToolResult, DCPError> {
            Ok(ToolResult::success(vec![self.schema.id as u8]))
        }

        fn schema(&self) -> &ToolSchema {
            &self.schema
        }
    }

    #[test]
    fn test_register_and_dispatch() {
        let mut router = BinaryTrieRouter::new();

        let handler = Box::new(TestHandler::new(1, "test_tool"));
        router.register(handler).unwrap();

        assert!(router.has_tool(1));
        assert!(!router.has_tool(0));
        assert!(!router.has_tool(2));

        let dispatched = router.dispatch(1).unwrap();
        assert_eq!(dispatched.tool_id(), 1);
    }

    #[test]
    fn test_resolve_name() {
        let mut router = BinaryTrieRouter::new();

        router
            .register(Box::new(TestHandler::new(42, "my_tool")))
            .unwrap();

        assert_eq!(router.resolve_name("my_tool"), Some(42));
        assert_eq!(router.resolve_name("unknown"), None);
    }

    #[test]
    fn test_raw_execute_is_deny_by_default() {
        let mut router = BinaryTrieRouter::new();
        router
            .register(Box::new(TestHandler::new(5, "exec_test")))
            .unwrap();

        let args = SharedArgs::new(&[], 0);
        let result = router.execute(5, &args);

        assert_eq!(result, Err(DCPError::CapabilityDenied));
    }

    #[test]
    fn test_raw_execute_hides_tool_existence() {
        let router = BinaryTrieRouter::new();
        let args = SharedArgs::new(&[], 0);

        let result = router.execute(999, &args);
        assert_eq!(result, Err(DCPError::CapabilityDenied));
    }

    #[test]
    fn test_multiple_tools() {
        let mut router = BinaryTrieRouter::new();

        for i in 0..10 {
            let name: &'static str = Box::leak(format!("tool_{}", i).into_boxed_str());
            router
                .register(Box::new(TestHandler::new(i, name)))
                .unwrap();
        }

        assert_eq!(router.tool_count(), 10);
        assert_eq!(router.max_tool_id(), 9);

        for i in 0..10 {
            assert!(router.has_tool(i));
        }
    }

    #[test]
    fn test_sparse_registration() {
        let mut router = BinaryTrieRouter::new();

        router
            .register(Box::new(TestHandler::new(0, "first")))
            .unwrap();
        router
            .register(Box::new(TestHandler::new(100, "hundredth")))
            .unwrap();
        router
            .register(Box::new(TestHandler::new(1000, "thousandth")))
            .unwrap();

        assert_eq!(router.tool_count(), 3);
        assert!(router.has_tool(0));
        assert!(router.has_tool(100));
        assert!(router.has_tool(1000));
        assert!(!router.has_tool(50));
    }
}
