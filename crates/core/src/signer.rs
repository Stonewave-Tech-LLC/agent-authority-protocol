//! Key custody abstraction. v1 ships only `LocalSigner` (key held in
//! process memory) — fine for a demo, not for anything holding real
//! liability. The trait is the point: a KMS/HSM-backed `Signer` can be
//! dropped in later without touching any caller (issuance, message signing).
//! On real devices, "Secure Enclave-backed P-256 key" is itself such a
//! drop-in: the signing operation happens inside hardware this process
//! never sees, `LocalSigner` is only for server-side / demo keys.

use rand::rngs::OsRng;
use serde::Serialize;

use crate::jws::{self, JwsError};
use crate::keys::SigningKey as Key;
use crate::types::PublicKeyJwk;

pub trait Signer {
    fn sign_payload<T: Serialize>(&self, payload: &T) -> Result<String, JwsError>;
    fn public_jwk(&self) -> PublicKeyJwk;
}

#[derive(Clone)]
pub struct LocalSigner {
    key: Key,
}

impl LocalSigner {
    /// Ed25519 — the default for server-held agent keys (ace, stella, ...).
    pub fn generate() -> Self {
        Self::generate_ed25519()
    }

    pub fn generate_ed25519() -> Self {
        let mut csprng = OsRng;
        Self {
            key: Key::Ed25519(ed25519_dalek::SigningKey::generate(&mut csprng)),
        }
    }

    /// P-256 — the format required for a Secure Enclave-backed device key.
    /// `LocalSigner` holding a P-256 key is only useful for tests/the CLI
    /// demo; a real device's private key must never leave its Secure
    /// Enclave, so real device Signers are a separate (hardware-backed)
    /// impl of this same trait, not this one.
    pub fn generate_p256() -> Self {
        let mut csprng = OsRng;
        Self {
            key: Key::P256(p256::ecdsa::SigningKey::random(&mut csprng)),
        }
    }

    pub fn from_ed25519_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            key: Key::Ed25519(ed25519_dalek::SigningKey::from_bytes(bytes)),
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
