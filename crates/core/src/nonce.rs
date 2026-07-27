//! Replay protection. A signed AgentMessage is only good once, for the
//! Verifier it names as `audience`. Same swappable-trait treatment as the
//! rest of the I/O boundaries.

use std::collections::HashSet;
use std::sync::RwLock;

pub trait NonceStore {
    /// Returns `true` if (agent_id, nonce) was already seen (i.e. this is a
    /// replay and must be rejected), and records it as seen either way.
    fn seen_and_record(&self, agent_id: &str, nonce: &str) -> bool;
}

#[derive(Default)]
pub struct InMemoryNonceStore {
    seen: RwLock<HashSet<(String, String)>>,
}

impl InMemoryNonceStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl NonceStore for InMemoryNonceStore {
    fn seen_and_record(&self, agent_id: &str, nonce: &str) -> bool {
        let mut guard = self.seen.write().expect("nonce lock poisoned");
        !guard.insert((agent_id.to_string(), nonce.to_string()))
    }
}
