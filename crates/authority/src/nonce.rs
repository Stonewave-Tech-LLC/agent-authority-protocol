//! Replay protection for agent-generated nonces (0004 V5: "unseen within
//! the freshness window"). A nonce only has to be remembered until the key
//! binding that carried it is too old to be accepted anyway, so the store
//! never grows without bound (v0 bug 3).

use std::collections::HashMap;
use std::sync::Mutex;

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("nonce store: {0}")]
pub struct NonceStoreError(pub String);

pub trait NonceStore {
    /// Atomically records `nonce` until `expires_at` and returns `true`, or
    /// returns `false` if it is already recorded and not yet expired. Two
    /// concurrent presentations with the same nonce must not both get
    /// `true`.
    fn check_and_insert(
        &self,
        nonce: &str,
        expires_at: i64,
        now: i64,
    ) -> Result<bool, NonceStoreError>;
}

/// A process-local store, for tests and single-instance verifiers.
#[derive(Debug, Default)]
pub struct MemoryNonceStore {
    seen: Mutex<HashMap<String, i64>>,
}

impl NonceStore for MemoryNonceStore {
    fn check_and_insert(
        &self,
        nonce: &str,
        expires_at: i64,
        now: i64,
    ) -> Result<bool, NonceStoreError> {
        let mut seen = self
            .seen
            .lock()
            .map_err(|_| NonceStoreError("lock poisoned".into()))?;
        seen.retain(|_, exp| *exp > now);
        if seen.contains_key(nonce) {
            return Ok(false);
        }
        seen.insert(nonce.to_owned(), expires_at);
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_nonce_is_accepted_once_until_it_expires() {
        let store = MemoryNonceStore::default();
        assert!(store.check_and_insert("n", 100, 0).unwrap());
        assert!(!store.check_and_insert("n", 100, 50).unwrap());
        assert!(store.check_and_insert("n", 300, 100).unwrap());
        assert_eq!(store.seen.lock().unwrap().len(), 1);
    }
}
