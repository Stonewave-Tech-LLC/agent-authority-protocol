//! Minimal compact JWS (RFC 7515) over Ed25519 (EdDSA). Deliberately not using
//! a generic JWT claims library: the payload here is our own typed Delegation
//! / AgentMessage struct, not a claims bag, and keeping the envelope this thin
//! keeps the trust-critical path auditable in ~80 lines.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine as _};
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use serde::{de::DeserializeOwned, Serialize};
use thiserror::Error;

use crate::types::PublicKeyJwk;

const HEADER: &str = r#"{"alg":"EdDSA","typ":"JWT"}"#;

#[derive(Debug, Error)]
pub enum JwsError {
    #[error("malformed compact JWS (expected 3 dot-separated segments)")]
    Malformed,
    #[error("unsupported or unexpected header: {0}")]
    UnsupportedHeader(String),
    #[error("base64 decode failed: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("json (de)serialization failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("signature verification failed")]
    BadSignature,
    #[error("invalid key material: {0}")]
    BadKey(String),
}

pub fn sign<T: Serialize>(payload: &T, key: &SigningKey) -> Result<String, JwsError> {
    let header_b64 = B64.encode(HEADER.as_bytes());
    let payload_b64 = B64.encode(serde_json::to_vec(payload)?);
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature: Signature = key.sign(signing_input.as_bytes());
    let sig_b64 = B64.encode(signature.to_bytes());
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
    if header.get("alg").and_then(|v| v.as_str()) != Some("EdDSA") {
        return Err(JwsError::UnsupportedHeader(header.to_string()));
    }

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig_bytes = B64.decode(parts[2])?;
    let sig_array: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| JwsError::BadKey("signature is not 64 bytes".into()))?;
    let signature = Signature::from_bytes(&sig_array);

    key.verify(signing_input.as_bytes(), &signature)
        .map_err(|_| JwsError::BadSignature)?;

    let payload_bytes = B64.decode(parts[1])?;
    Ok(serde_json::from_slice(&payload_bytes)?)
}

pub fn public_key_to_jwk(key: &VerifyingKey) -> PublicKeyJwk {
    PublicKeyJwk {
        kty: "OKP".to_string(),
        crv: "Ed25519".to_string(),
        x: B64.encode(key.to_bytes()),
    }
}

pub fn jwk_to_public_key(jwk: &PublicKeyJwk) -> Result<VerifyingKey, JwsError> {
    if jwk.kty != "OKP" || jwk.crv != "Ed25519" {
        return Err(JwsError::BadKey(format!(
            "unsupported key type {}/{}",
            jwk.kty, jwk.crv
        )));
    }
    let bytes = B64.decode(&jwk.x)?;
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| JwsError::BadKey("Ed25519 public key is not 32 bytes".into()))?;
    VerifyingKey::from_bytes(&array).map_err(|e| JwsError::BadKey(e.to_string()))
}
