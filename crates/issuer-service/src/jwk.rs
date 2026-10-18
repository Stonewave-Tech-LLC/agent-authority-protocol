//! Strict handling of the principal's public key: EC P-256 only, canonical
//! encodings only, RFC 7638 thumbprint computed from the validated values.

use aap_core::{jws, PublicKeyJwk, VerifyingKey};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// Wire form of a JWK. Unknown members are rejected rather than ignored.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JwkIn {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: String,
}

pub struct ValidJwk {
    pub jwk: PublicKeyJwk,
    pub thumbprint: [u8; 32],
    pub key: VerifyingKey,
}

fn canonical_coordinate(s: &str) -> bool {
    // 32 bytes encode to exactly 43 unpadded base64url characters; decoding
    // is strict about trailing bits, and re-encoding must round-trip.
    s.len() == 43
        && B64
            .decode(s)
            .is_ok_and(|b| b.len() == 32 && B64.encode(&b) == s)
}

pub fn validate(input: &JwkIn) -> Result<ValidJwk, &'static str> {
    if input.kty != "EC" || input.crv != "P-256" {
        return Err("jwk_not_p256");
    }
    if !canonical_coordinate(&input.x) || !canonical_coordinate(&input.y) {
        return Err("jwk_bad_coordinates");
    }
    let jwk = PublicKeyJwk {
        kty: input.kty.clone(),
        crv: input.crv.clone(),
        x: input.x.clone(),
        y: Some(input.y.clone()),
    };
    // Rejects points that are not on the curve.
    let key = jws::jwk_to_public_key(&jwk).map_err(|_| "jwk_not_on_curve")?;
    Ok(ValidJwk {
        thumbprint: thumbprint(&input.x, &input.y),
        jwk,
        key,
    })
}

/// RFC 7638 thumbprint of an EC key: SHA-256 over the canonical JSON with
/// members in lexicographic order and no whitespace.
pub fn thumbprint(x: &str, y: &str) -> [u8; 32] {
    let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
    Sha256::digest(canonical.as_bytes()).into()
}
