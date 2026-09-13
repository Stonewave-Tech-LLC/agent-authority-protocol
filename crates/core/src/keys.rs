//! Algorithm-agnostic key wrappers. Two signature algorithms are supported:
//! Ed25519 (EdDSA) for software-held keys, and ECDSA P-256 (ES256) because
//! that is the only asymmetric algorithm a phone/laptop Secure Enclave can
//! actually produce — a Secure Enclave-backed device key can never be
//! Ed25519. Everything above this module (token.rs, verifier.rs,
//! resolver.rs) is written against these enums, never against a concrete
//! curve type, so adding a third algorithm later stays a one-file change.

use ed25519_dalek::{Signature as Ed25519Signature, Signer, Verifier};
use p256::ecdsa::Signature as P256Signature;

#[derive(Clone)]
pub enum SigningKey {
    Ed25519(ed25519_dalek::SigningKey),
    P256(p256::ecdsa::SigningKey),
}

#[derive(Clone)]
pub enum VerifyingKey {
    Ed25519(ed25519_dalek::VerifyingKey),
    P256(p256::ecdsa::VerifyingKey),
}

/// The JWS `alg` header value each variant must be signed/verified under.
/// Never inferred from key shape alone — the header is checked explicitly
/// against this before any cryptographic verification runs, so a P-256
/// signature can never be silently accepted as if it were Ed25519 or vice
/// versa (classic JWS "alg confusion" is a header/key *pairing* check, not
/// just "does the math work out").
impl SigningKey {
    pub fn alg(&self) -> &'static str {
        match self {
            SigningKey::Ed25519(_) => "EdDSA",
            SigningKey::P256(_) => "ES256",
        }
    }

    pub fn sign_bytes(&self, msg: &[u8]) -> Vec<u8> {
        match self {
            SigningKey::Ed25519(k) => {
                let sig: Ed25519Signature = k.sign(msg);
                sig.to_bytes().to_vec()
            }
            SigningKey::P256(k) => {
                // Fixed-size r||s (IEEE P1363 / JOSE) encoding, 64 bytes —
                // NOT DER. This is what ES256 in JWS requires.
                let sig: P256Signature = k.sign(msg);
                sig.to_bytes().to_vec()
            }
        }
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        match self {
            SigningKey::Ed25519(k) => VerifyingKey::Ed25519(k.verifying_key()),
            SigningKey::P256(k) => VerifyingKey::P256(*k.verifying_key()),
        }
    }
}

impl VerifyingKey {
    pub fn alg(&self) -> &'static str {
        match self {
            VerifyingKey::Ed25519(_) => "EdDSA",
            VerifyingKey::P256(_) => "ES256",
        }
    }

    /// `alg` must already have been checked by the caller against
    /// `self.alg()` — this only does the cryptographic check.
    pub fn verify_bytes(&self, msg: &[u8], sig_bytes: &[u8]) -> bool {
        match self {
            VerifyingKey::Ed25519(k) => {
                let Ok(sig_array): Result<[u8; 64], _> = sig_bytes.try_into() else {
                    return false;
                };
                let sig = Ed25519Signature::from_bytes(&sig_array);
                k.verify(msg, &sig).is_ok()
            }
            VerifyingKey::P256(k) => {
                let Ok(sig) = P256Signature::from_slice(sig_bytes) else {
                    return false;
                };
                k.verify(msg, &sig).is_ok()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jws;

    #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
    struct Payload {
        hello: String,
    }

    #[test]
    fn p256_round_trips_through_jws_sign_and_verify() {
        let signing = SigningKey::P256(p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng));
        let verifying = signing.verifying_key();
        let payload = Payload {
            hello: "secure enclave".into(),
        };

        let jws = jws::sign(&payload, &signing).unwrap();
        let out: Payload = jws::verify(&jws, &verifying).unwrap();
        assert_eq!(out, payload);
    }

    #[test]
    fn p256_jwk_round_trips() {
        let signing = SigningKey::P256(p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng));
        let verifying = signing.verifying_key();

        let jwk = jws::public_key_to_jwk(&verifying);
        assert_eq!(jwk.kty, "EC");
        assert_eq!(jwk.crv, "P-256");
        assert!(jwk.y.is_some(), "P-256 JWK must carry y, unlike OKP keys");

        let recovered = jws::jwk_to_public_key(&jwk).unwrap();
        let payload = Payload {
            hello: "round trip".into(),
        };
        let signed = jws::sign(&payload, &signing).unwrap();
        // Verifying against the key rebuilt from its own JWK must behave
        // identically to verifying against the original in-memory key.
        let out: Payload = jws::verify(&signed, &recovered).unwrap();
        assert_eq!(out, payload);
    }

    #[test]
    fn ed25519_signature_is_rejected_by_a_p256_key_not_silently_coerced() {
        // Alg-confusion guard: a JWS signed under EdDSA must never verify
        // against a P-256 VerifyingKey, and vice versa, even if both keys
        // happen to be held by the "same" logical agent during a migration.
        let ed25519_signing =
            SigningKey::Ed25519(ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng));
        let p256_signing =
            SigningKey::P256(p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng));
        let p256_verifying = p256_signing.verifying_key();

        let payload = Payload {
            hello: "attacker controlled".into(),
        };
        let jws_signed_as_ed25519 = jws::sign(&payload, &ed25519_signing).unwrap();

        let result: Result<Payload, _> = jws::verify(&jws_signed_as_ed25519, &p256_verifying);
        assert!(matches!(result, Err(jws::JwsError::AlgorithmMismatch)));
    }

    #[test]
    fn ed25519_still_works_unchanged() {
        let signing =
            SigningKey::Ed25519(ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng));
        let verifying = signing.verifying_key();
        let payload = Payload {
            hello: "software key".into(),
        };
        let jws = jws::sign(&payload, &signing).unwrap();
        let out: Payload = jws::verify(&jws, &verifying).unwrap();
        assert_eq!(out, payload);

        let jwk = jws::public_key_to_jwk(&verifying);
        assert_eq!(jwk.kty, "OKP");
        assert!(jwk.y.is_none(), "Ed25519 JWK must not carry y");
    }
}
