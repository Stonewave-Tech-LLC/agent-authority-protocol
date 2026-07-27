//! Revocation status. v1 checks an in-memory set rather than making an HTTP
//! call to `delegation.status_endpoint` — keeps the core crate sync and
//! dependency-light. A real deployment implements `StatusChecker` against
//! that endpoint (or, longer-term, IETF Token Status List).

use std::collections::HashSet;
use std::sync::RwLock;
use uuid::Uuid;

pub trait StatusChecker {
    fn is_revoked(&self, delegation_id: &Uuid) -> bool;
}

#[derive(Default)]
pub struct InMemoryStatus {
    revoked: RwLock<HashSet<Uuid>>,
}

impl InMemoryStatus {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn revoke(&self, delegation_id: Uuid) {
        self.revoked
            .write()
            .expect("status lock poisoned")
            .insert(delegation_id);
    }
}

impl StatusChecker for InMemoryStatus {
    fn is_revoked(&self, delegation_id: &Uuid) -> bool {
        self.revoked
            .read()
            .expect("status lock poisoned")
            .contains(delegation_id)
    }
}
