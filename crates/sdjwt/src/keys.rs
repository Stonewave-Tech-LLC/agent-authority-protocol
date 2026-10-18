//! Keys and algorithms. ES256 is mandatory (it is the only algorithm phone
//! secure hardware supports, and AP2 uses it); EdDSA stays allowed for
//! server-held keys. The algorithm is pinned per key: a JWS header's `alg`
//! is compared against `VerifyingKey::algorithm()` before any signature
//! check runs (see `jws.rs`), never inferred from the token.
//!
//! This mirrors `aap-core`'s `keys.rs` on purpose: `aap-core` will depend on
//! this crate (it only accepts a `VerifiedChain`), so this crate cannot depend
//! on `aap-core` and carries its own copy of the two-variant key enums.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine as _};
use ed25519_dalek::Signer as _;
use p256::ecdsa::signature::RandomizedSigner as _;
use p256::ecdsa::signature::Verifier as _;
use rand::rngs::OsRng;
use serde_json::{json, Value};

use crate::error::ErrorKind;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// ECDSA P-256 with SHA-256, signature as fixed-size r||s (64 bytes).
    Es256,
    /// Ed25519.
    EdDsa,
}

impl Algorithm {
    /// The JWS `alg` header value.
    pub fn as_str(self) -> &'static str {
        match self {
            Algorithm::Es256 => "ES256",
            Algorithm::EdDsa => "EdDSA",
        }
    }
}

/// Anything that can produce a JWS signature: a software key here, a Secure
/// Enclave or KMS key elsewhere. The private key never has to be visible to
/// this crate.
pub trait Signer {
    fn algorithm(&self) -> Algorithm;

    /// Signs the JWS signing input (`<b64 header>.<b64 payload>`). ES256
    /// signatures must be the 64-byte r||s form JWS requires, not DER.
    fn sign(&self, signing_input: &[u8]) -> Result<Vec<u8>, ErrorKind>;
}

/// A software-held private key. Fine for issuers, tests and server-side
/// agents; a device's user key lives in hardware behind its own `Signer`.
#[derive(Clone)]
pub enum SigningKey {
    Ed25519(ed25519_dalek::SigningKey),
    P256(p256::ecdsa::SigningKey),
}

impl SigningKey {
    pub fn generate_p256() -> Self {
        SigningKey::P256(p256::ecdsa::SigningKey::random(&mut OsRng))
    }

    pub fn generate_ed25519() -> Self {
        SigningKey::Ed25519(ed25519_dalek::SigningKey::generate(&mut OsRng))
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        match self {
            SigningKey::Ed25519(k) => VerifyingKey::Ed25519(k.verifying_key()),
            SigningKey::P256(k) => VerifyingKey::P256(*k.verifying_key()),
        }
    }
}

impl Signer for SigningKey {
    fn algorithm(&self) -> Algorithm {
        match self {
            SigningKey::Ed25519(_) => Algorithm::EdDsa,
            SigningKey::P256(_) => Algorithm::Es256,
        }
    }

    fn sign(&self, signing_input: &[u8]) -> Result<Vec<u8>, ErrorKind> {
        Ok(match self {
            SigningKey::Ed25519(k) => k.sign(signing_input).to_bytes().to_vec(),
            // Hedged (randomized) ECDSA rather than plain RFC 6979: two
            // signatures over the same mandate differ, so the hash of a
            // signed mandate cannot be guessed from its content alone.
            SigningKey::P256(k) => {
                let sig: p256::ecdsa::Signature = k.sign_with_rng(&mut OsRng, signing_input);
                sig.to_bytes().to_vec()
            }
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyingKey {
    Ed25519(ed25519_dalek::VerifyingKey),
    P256(p256::ecdsa::VerifyingKey),
}

impl VerifyingKey {
    pub fn algorithm(&self) -> Algorithm {
        match self {
            VerifyingKey::Ed25519(_) => Algorithm::EdDsa,
            VerifyingKey::P256(_) => Algorithm::Es256,
        }
    }

    /// Only the cryptographic check. The caller must already have matched
    /// the header's `alg` against `self.algorithm()`.
    pub(crate) fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        match self {
            VerifyingKey::Ed25519(k) => {
                let Ok(bytes) = <[u8; 64]>::try_from(sig) else {
                    return false;
                };
                // verify_strict rejects small-order keys and non-canonical
                // signatures, which plain verify tolerates.
                k.verify_strict(msg, &ed25519_dalek::Signature::from_bytes(&bytes))
                    .is_ok()
            }
            VerifyingKey::P256(k) => {
                let Ok(sig) = p256::ecdsa::Signature::from_slice(sig) else {
                    return false;
                };
                k.verify(msg, &sig).is_ok()
            }
        }
    }

    /// The public key as a JWK (RFC 7517), as it appears in `cnf.jwk`.
    pub fn to_jwk(&self) -> Value {
        match self {
            VerifyingKey::Ed25519(k) => json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "x": B64.encode(k.to_bytes()),
            }),
            VerifyingKey::P256(k) => {
                let point = k.to_encoded_point(false);
                json!({
                    "kty": "EC",
                    "crv": "P-256",
                    "x": B64.encode(point.x().expect("uncompressed point has x")),
                    "y": B64.encode(point.y().expect("uncompressed point has y")),
                })
            }
        }
    }

    /// A `cnf` claim value (RFC 7800) confirming this key by value.
    pub fn to_cnf(&self) -> Value {
        json!({ "jwk": self.to_jwk() })
    }

    /// Parses a public JWK. Members other than `kty`, `crv`, `x`, `y` and
    /// `alg` are ignored; an `alg` member, if present, must agree with the
    /// key type so a JWK cannot claim an algorithm its key cannot do.
    pub fn from_jwk(jwk: &Value) -> Result<Self, ErrorKind> {
        let obj = jwk
            .as_object()
            .ok_or_else(|| ErrorKind::BadKey("JWK is not an object".into()))?;
        let member = |name: &str| obj.get(name).and_then(Value::as_str);
        let coord = |name: &str| -> Result<[u8; 32], ErrorKind> {
            let s =
                member(name).ok_or_else(|| ErrorKind::BadKey(format!("JWK is missing {name}")))?;
            let bytes = B64.decode(s).map_err(|_| ErrorKind::Base64)?;
            <[u8; 32]>::try_from(bytes.as_slice())
                .map_err(|_| ErrorKind::BadKey(format!("JWK {name} is not 32 bytes")))
        };
        let key = match (member("kty"), member("crv")) {
            (Some("EC"), Some("P-256")) => {
                let (x, y) = (coord("x")?, coord("y")?);
                let point =
                    p256::EncodedPoint::from_affine_coordinates(&x.into(), &y.into(), false);
                let key = p256::ecdsa::VerifyingKey::from_encoded_point(&point)
                    .map_err(|e| ErrorKind::BadKey(e.to_string()))?;
                VerifyingKey::P256(key)
            }
            (Some("OKP"), Some("Ed25519")) => {
                let key = ed25519_dalek::VerifyingKey::from_bytes(&coord("x")?)
                    .map_err(|e| ErrorKind::BadKey(e.to_string()))?;
                VerifyingKey::Ed25519(key)
            }
            (kty, crv) => {
                return Err(ErrorKind::BadKey(format!(
                    "unsupported key type {kty:?}/{crv:?}"
                )))
            }
        };
        match obj.get("alg") {
            None => Ok(key),
            Some(Value::String(a)) if a == key.algorithm().as_str() => Ok(key),
            Some(other) => Err(ErrorKind::BadKey(format!(
                "JWK alg {other} does not match its key type"
            ))),
        }
    }

    /// Reads the key out of a `cnf` claim. Only the `jwk` confirmation
    /// method is supported; `kid`, `jkt` and friends would need a resolver
    /// this format layer deliberately does not have.
    pub(crate) fn from_cnf(cnf: &Value) -> Result<Self, ErrorKind> {
        let jwk = cnf
            .as_object()
            .and_then(|c| c.get("jwk"))
            .ok_or_else(|| ErrorKind::BadKey("cnf has no jwk member".into()))?;
        Self::from_jwk(jwk)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jwk_round_trips_for_both_algorithms() {
        for key in [SigningKey::generate_p256(), SigningKey::generate_ed25519()] {
            let vk = key.verifying_key();
            assert_eq!(VerifyingKey::from_jwk(&vk.to_jwk()).unwrap(), vk);
            assert_eq!(VerifyingKey::from_cnf(&vk.to_cnf()).unwrap(), vk);
        }
    }

    #[test]
    fn jwk_alg_member_must_match_key_type() {
        let vk = SigningKey::generate_p256().verifying_key();
        let mut jwk = vk.to_jwk();
        jwk["alg"] = json!("ES256");
        assert!(VerifyingKey::from_jwk(&jwk).is_ok());
        jwk["alg"] = json!("EdDSA");
        assert!(matches!(
            VerifyingKey::from_jwk(&jwk),
            Err(ErrorKind::BadKey(_))
        ));
    }

    #[test]
    fn p256_point_must_be_on_the_curve() {
        let vk = SigningKey::generate_p256().verifying_key();
        let mut jwk = vk.to_jwk();
        jwk["y"] = json!(B64.encode([7u8; 32]));
        assert!(VerifyingKey::from_jwk(&jwk).is_err());
    }

    #[test]
    fn signatures_verify_and_reject_tampering() {
        for key in [SigningKey::generate_p256(), SigningKey::generate_ed25519()] {
            let sig = key.sign(b"a.b").unwrap();
            assert_eq!(sig.len(), 64);
            assert!(key.verifying_key().verify(b"a.b", &sig));
            assert!(!key.verifying_key().verify(b"a.c", &sig));
        }
    }
}
