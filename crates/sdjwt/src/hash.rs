//! The `_sd_alg` hash (RFC 9901 §4.1.1). sha-256 is the default and the
//! only one that must be supported; sha-384 and sha-512 cost nothing extra
//! with `sha2` and are accepted. Anything else is rejected, never ignored.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine as _};
use serde_json::Value;
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::error::ErrorKind;
use crate::jws::Object;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SdAlg {
    #[default]
    Sha256,
    Sha384,
    Sha512,
}

impl SdAlg {
    /// The IANA "Hash Name String", as written in `_sd_alg`.
    pub fn name(self) -> &'static str {
        match self {
            SdAlg::Sha256 => "sha-256",
            SdAlg::Sha384 => "sha-384",
            SdAlg::Sha512 => "sha-512",
        }
    }

    pub(crate) fn from_name(name: &str) -> Result<Self, ErrorKind> {
        match name {
            "sha-256" => Ok(SdAlg::Sha256),
            "sha-384" => Ok(SdAlg::Sha384),
            "sha-512" => Ok(SdAlg::Sha512),
            other => Err(ErrorKind::UnsupportedSdAlg(other.to_owned())),
        }
    }

    /// `_sd_alg` from the top level of a JWT payload, sha-256 if absent.
    pub(crate) fn of_payload(payload: &Object) -> Result<Self, ErrorKind> {
        match payload.get("_sd_alg") {
            None => Ok(SdAlg::Sha256),
            Some(Value::String(name)) => Self::from_name(name),
            Some(_) => Err(ErrorKind::InvalidClaim("_sd_alg")),
        }
    }

    /// base64url(hash(US-ASCII bytes of `input`)), the digest form used for
    /// disclosures, `sd_hash` and `issuer_jwt_hash` alike.
    pub fn digest(self, input: &str) -> String {
        let bytes = input.as_bytes();
        match self {
            SdAlg::Sha256 => B64.encode(Sha256::digest(bytes)),
            SdAlg::Sha384 => B64.encode(Sha384::digest(bytes)),
            SdAlg::Sha512 => B64.encode(Sha512::digest(bytes)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc9901_section_4_2_3_digest() {
        let disclosure = "WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0";
        assert_eq!(
            SdAlg::Sha256.digest(disclosure),
            "X9yH0Ajrdm1Oij4tWso9UzzKJvPoDxwmuEcO3XAdRC0"
        );
    }

    #[test]
    fn unknown_alg_is_rejected() {
        let mut payload = Object::new();
        payload.insert("_sd_alg".into(), "md5".into());
        assert_eq!(
            SdAlg::of_payload(&payload),
            Err(ErrorKind::UnsupportedSdAlg("md5".into()))
        );
    }
}
