//! Bounded JSON-RPC request replay tracking for side-effecting MCP calls.

use std::collections::{HashSet, VecDeque};

/// Default number of side-effecting JSON-RPC request ids retained per adapter session.
pub(crate) const DEFAULT_REQUEST_REPLAY_WINDOW: usize = 1024;

#[derive(Debug, Clone)]
pub(crate) struct RequestReplayGuard {
    seen: HashSet<String>,
    order: VecDeque<String>,
    max_entries: usize,
}

impl RequestReplayGuard {
    pub(crate) fn new(max_entries: usize) -> Self {
        Self {
            seen: HashSet::new(),
            order: VecDeque::new(),
            max_entries,
        }
    }

    pub(crate) fn check_and_record(&mut self, key: String) -> bool {
        if self.seen.contains(&key) {
            return false;
        }

        self.seen.insert(key.clone());
        self.order.push_back(key);

        while self.order.len() > self.max_entries {
            if let Some(expired) = self.order.pop_front() {
                self.seen.remove(&expired);
            }
        }

        true
    }
}

impl Default for RequestReplayGuard {
    fn default() -> Self {
        Self::new(DEFAULT_REQUEST_REPLAY_WINDOW)
    }
}

pub(crate) fn replay_key(method: &str, request_id: &str) -> String {
    format!("{method}:{request_id}")
}
