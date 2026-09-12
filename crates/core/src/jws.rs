//! Minimal compact JWS (RFC 7515) over two algorithms: Ed25519 (EdDSA) and
//! ECDSA P-256 (ES256, needed because a Secure Enclave can only ever produce
//! P-256 keys, never Ed25519 — see keys.rs). Deliberately not using a
//! generic JWT claims library: the payload here is our own typed Delegation
//! / AgentMessage struct, not a claims bag, and keeping the envelope this
//! thin keeps the trust-critical path auditable.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine as _};
use serde::{de::DeserializeOwned, Serialize};
use thiserror::Error;

use crate::keys::{SigningKey, VerifyingKey};
use crate::types::PublicKeyJwk;

#[derive(Debug, Error)]
pub enum JwsError {
    #[error("malformed compact JWS (expected 3 dot-separated segments)")]
    Malformed,
    #[error("unsupported or unexpected header: {0}")]
    UnsupportedHeader(String),
    #[error("JWS alg header does not match the verifying key's algorithm")]
    AlgorithmMismatch,
    #[error("base64 decode failed: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("json (de)serialization failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("signature verification failed")]
    BadSignature,
    #[error("invalid key material: {0}")]
    BadKey(String),
}

fn header_for(alg: &str) -> String {
    format!(r#"{{"alg":"{alg}","typ":"JWT"}}"#)
}

pub fn sign<T: Serialize>(payload: &T, key: &SigningKey) -> Result<String, JwsError> {
    let header_b64 = B64.encode(header_for(key.alg()).as_bytes());
    let payload_b64 = B64.encode(serde_json::to_vec(payload)?);
    let signing_input = format!("{header_b64}.{payload_b64}");
    let sig_bytes = key.sign_bytes(signing_input.as_bytes());
    let sig_b64 = B64.encode(sig_bytes);
    Ok(format!("{signing_input}.{sig_b64}"))
}

/// Decodes the payload without checking the signature. Callers must treat
/// the result as untrusted until `verify` succeeds — this exists only so the
/// typestate layer (`token.rs`) can inspect an Unverified token to figure out
/// *which* key to verify against (e.g. resolving the principal from the id).
pub fn decode_unverified<T: DeserializeOwned>(jws: &str) -> Result<T, JwsError> {
    let parts: Vec<&str> = jws.split('.').collect();
    if parts.len() != 3 {
        return Err(JwsError::Malformed);
    }
    let payload_bytes = B64.decode(parts[1])?;
    Ok(serde_json::from_slice(&payload_bytes)?)
}

pub fn verify<T: DeserializeOwned>(jws: &str, key: &VerifyingKey) -> Result<T, JwsError> {
    let parts: Vec<&str> = jws.split('.').collect();
    if parts.len() != 3 {
        return Err(JwsError::Malformed);
    }
    let header_bytes = B64.decode(parts[0])?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes)?;
    let alg = header.get("alg").and_then(|v| v.as_str());

    // The header's alg must name exactly the algorithm the caller's
    // VerifyingKey variant actually is — never inferred from the key shape,
    // never "try each algorithm until one works". This is what closes the
    // classic JWS alg-confusion hole: presenting an ES256 signature does not
    // get evaluated against an Ed25519 key's byte layout, and vice versa.
    match alg {
        Some(a) if a == key.alg() => {}
        Some(_) => return Err(JwsError::AlgorithmMismatch),
        None => return Err(JwsError::UnsupportedHeader(header.to_string())),
    }

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig_bytes = B64.decode(parts[2])?;

    if !key.verify_bytes(signing_input.as_bytes(), &sig_bytes) {
        return Err(JwsError::BadSignature);
    }

    let payload_bytes = B64.decode(parts[1])?;
    Ok(serde_json::from_slice(&payload_bytes)?)
}

pub fn public_key_to_jwk(key: &VerifyingKey) -> PublicKeyJwk {
    match key {
        VerifyingKey::Ed25519(k) => PublicKeyJwk {
            kty: "OKP".to_string(),
            crv: "Ed25519".to_string(),
            x: B64.encode(k.to_bytes()),
            y: None,
        },
        VerifyingKey::P256(k) => {
            let point = k.to_encoded_point(false); // uncompressed: 0x04 || x || y
            let x = point.x().expect("uncompressed point always has x");
            let y = point.y().expect("uncompressed point always has y");
            PublicKeyJwk {
                kty: "EC".to_string(),
                crv: "P-256".to_string(),
                x: B64.encode(x),
                y: Some(B64.encode(y)),
            }
        }
    }
}

pub fn jwk_to_public_key(jwk: &PublicKeyJwk) -> Result<VerifyingKey, JwsError> {
    match (jwk.kty.as_str(), jwk.crv.as_str()) {
        ("OKP", "Ed25519") => {
            let bytes = B64.decode(&jwk.x)?;
            let array: [u8; 32] = bytes
                .try_into()
                .map_err(|_| JwsError::BadKey("Ed25519 public key is not 32 bytes".into()))?;
            let key = ed25519_dalek::VerifyingKey::from_bytes(&array)
                .map_err(|e| JwsError::BadKey(e.to_string()))?;
            Ok(VerifyingKey::Ed25519(key))
        }
        ("EC", "P-256") => {
            let y = jwk
                .y
                .as_ref()
                .ok_or_else(|| JwsError::BadKey("P-256 JWK is missing y".into()))?;
            let x_bytes = B64.decode(&jwk.x)?;
            let y_bytes = B64.decode(y)?;
            if x_bytes.len() != 32 || y_bytes.len() != 32 {
                return Err(JwsError::BadKey(
                    "P-256 x/y coordinates must be 32 bytes each".into(),
                ));
            }
            let mut sec1 = Vec::with_capacity(65);
            sec1.push(0x04); // uncompressed point marker
            sec1.extend_from_slice(&x_bytes);
            sec1.extend_from_slice(&y_bytes);
            let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1)
                .map_err(|e| JwsError::BadKey(e.to_string()))?;
            Ok(VerifyingKey::P256(key))
        }
        (kty, crv) => Err(JwsError::BadKey(format!(
            "unsupported key type {kty}/{crv}"
        ))),
    }
}
