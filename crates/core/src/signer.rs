//! Key custody abstraction. v1 ships only `LocalSigner` (key held in
//! process memory) — fine for a demo, not for anything holding real
//! liability. The trait is the point: a KMS/HSM-backed `Signer` can be
//! dropped in later without touching any caller (issuance, message signing).

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use serde::Serialize;

use crate::jws::{self, JwsError};
use crate::types::PublicKeyJwk;

pub trait Signer {
    fn sign_payload<T: Serialize>(&self, payload: &T) -> Result<String, JwsError>;
    fn public_jwk(&self) -> PublicKeyJwk;
}

pub struct LocalSigner {
    key: SigningKey,
}

impl LocalSigner {
    pub fn generate() -> Self {
        let mut csprng = OsRng;
        Self {
            key: SigningKey::generate(&mut csprng),
        }
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            key: SigningKey::from_bytes(bytes),
        }
    }
}

impl Signer for LocalSigner {
    fn sign_payload<T: Serialize>(&self, payload: &T) -> Result<String, JwsError> {
        jws::sign(payload, &self.key)
    }

    fn public_jwk(&self) -> PublicKeyJwk {
        jws::public_key_to_jwk(&self.key.verifying_key())
    }
}
