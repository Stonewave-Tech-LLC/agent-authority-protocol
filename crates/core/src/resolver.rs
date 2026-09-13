//! Principal identity resolution. v1 ships an in-memory registry (stand-in
//! for a small JSON/SQLite-backed service). The trait is what lets this
//! become a DID resolver later without touching the Verifier.

use std::collections::HashMap;
use std::sync::RwLock;

use crate::jws::{jwk_to_public_key, JwsError};
use crate::keys::VerifyingKey;
use crate::types::PublicKeyJwk;

pub trait KeyResolver {
    fn resolve_principal_key(&self, principal_id: &str) -> Result<VerifyingKey, String>;
}

#[derive(Default)]
pub struct InMemoryRegistry {
    principals: RwLock<HashMap<String, PublicKeyJwk>>,
}

impl InMemoryRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&self, principal_id: impl Into<String>, key: PublicKeyJwk) {
        self.principals
            .write()
            .expect("registry lock poisoned")
            .insert(principal_id.into(), key);
    }
}

impl KeyResolver for InMemoryRegistry {
    fn resolve_principal_key(&self, principal_id: &str) -> Result<VerifyingKey, String> {
        let guard = self.principals.read().expect("registry lock poisoned");
        let jwk = guard
            .get(principal_id)
            .ok_or_else(|| format!("unknown principal_id: {principal_id}"))?;
        jwk_to_public_key(jwk).map_err(|e: JwsError| e.to_string())
    }
}
