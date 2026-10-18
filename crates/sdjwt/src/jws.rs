//! Compact JWS (RFC 7515), hand-rolled like `aap-core`'s `jws.rs`: two
//! algorithms, header checks before any cryptography, nothing else.
//!
//! Checks, in this order, before a signature is ever computed:
//! 1. `typ` is one of the values allowed at this position of the
//!    presentation (`check_typ`). Media types compare case-insensitively and
//!    an `application/` prefix is optional (RFC 7515 §4.1.9).
//! 2. `alg` names exactly the algorithm of the caller's key. `none`, a
//!    missing `alg`, or the other algorithm all fail as `AlgorithmMismatch`.
//! 3. `crit` is absent: this implementation understands no extensions, so
//!    any critical header must be rejected (RFC 7515 §4.1.11).

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine as _};
use serde_json::{Map, Value};

use crate::error::ErrorKind;
use crate::keys::{Signer, VerifyingKey};

pub(crate) type Object = Map<String, Value>;

/// A parsed, *not yet verified* compact JWS. Header and payload are decoded
/// so the caller can route (which key, which position) before verifying.
#[derive(Debug, Clone)]
pub(crate) struct Jws {
    raw: String,
    header: Object,
    payload: Object,
}

/// Header, payload and signature segments, each non-empty. Used by the
/// presentation splitter to tell a JWT component from a disclosure.
pub(crate) fn looks_like_jwt(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 3 && parts.iter().all(|p| !p.is_empty())
}

fn decode_object(segment: &str) -> Result<Object, ErrorKind> {
    let bytes = B64.decode(segment).map_err(|_| ErrorKind::Base64)?;
    match serde_json::from_slice(&bytes).map_err(|e| ErrorKind::Json(e.to_string()))? {
        Value::Object(o) => Ok(o),
        _ => Err(ErrorKind::Json(
            "JWS header/payload is not an object".into(),
        )),
    }
}

impl Jws {
    pub(crate) fn parse(raw: &str) -> Result<Self, ErrorKind> {
        if !looks_like_jwt(raw) {
            return Err(ErrorKind::Malformed("JWT must have 3 non-empty segments"));
        }
        let mut parts = raw.split('.');
        let header = decode_object(parts.next().expect("3 segments"))?;
        let payload = decode_object(parts.next().expect("3 segments"))?;
        Ok(Jws {
            raw: raw.to_owned(),
            header,
            payload,
        })
    }

    pub(crate) fn raw(&self) -> &str {
        &self.raw
    }

    pub(crate) fn header(&self) -> &Object {
        &self.header
    }

    /// The payload exactly as signed. Unverified until `verify` succeeds.
    pub(crate) fn payload(&self) -> &Object {
        &self.payload
    }

    pub(crate) fn typ(&self) -> Option<&str> {
        self.header.get("typ").and_then(Value::as_str)
    }

    pub(crate) fn check_typ(&self, allowed: &[&str]) -> Result<(), ErrorKind> {
        let found = self.typ();
        let normalize = |t: &str| {
            let t = t.to_ascii_lowercase();
            match t.strip_prefix("application/") {
                Some(rest) => rest.to_owned(),
                None => t,
            }
        };
        match found {
            Some(t) if allowed.iter().any(|a| normalize(a) == normalize(t)) => Ok(()),
            _ => Err(ErrorKind::WrongTyp {
                expected: allowed.iter().map(|a| a.to_string()).collect(),
                found: self.header.get("typ").map(|v| match v {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                }),
            }),
        }
    }

    pub(crate) fn verify(&self, key: &VerifyingKey) -> Result<(), ErrorKind> {
        let expected = key.algorithm().as_str();
        match self.header.get("alg") {
            Some(Value::String(a)) if a == expected => {}
            other => {
                return Err(ErrorKind::AlgorithmMismatch {
                    expected,
                    found: other.map(|v| match v {
                        Value::String(s) => s.clone(),
                        v => v.to_string(),
                    }),
                })
            }
        }
        if self.header.contains_key("crit") {
            return Err(ErrorKind::UnsupportedHeader("crit".into()));
        }
        let (signing_input, sig_b64) = self
            .raw
            .rsplit_once('.')
            .expect("parse guaranteed 3 segments");
        let sig = B64.decode(sig_b64).map_err(|_| ErrorKind::Base64)?;
        if key.verify(signing_input.as_bytes(), &sig) {
            Ok(())
        } else {
            Err(ErrorKind::BadSignature)
        }
    }
}

/// Signs `payload` with `alg` and `typ` set from the signer and caller.
/// `extra` may add header parameters such as `kid`, but never `alg`, `typ`
/// or `crit`.
pub(crate) fn sign<S: Signer + ?Sized>(
    typ: &str,
    extra: &Object,
    payload: &Object,
    signer: &S,
) -> Result<String, ErrorKind> {
    if ["alg", "typ", "crit"]
        .iter()
        .any(|k| extra.contains_key(*k))
    {
        return Err(ErrorKind::Issuance(
            "alg, typ and crit header parameters are set by this crate",
        ));
    }
    let mut header = extra.clone();
    header.insert("alg".into(), signer.algorithm().as_str().into());
    header.insert("typ".into(), typ.into());
    let to_json = |o: &Object| serde_json::to_vec(o).map_err(|e| ErrorKind::Json(e.to_string()));
    let signing_input = format!(
        "{}.{}",
        B64.encode(to_json(&header)?),
        B64.encode(to_json(payload)?)
    );
    let sig = signer.sign(signing_input.as_bytes())?;
    Ok(format!("{signing_input}.{}", B64.encode(sig)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::SigningKey;
    use serde_json::json;

    fn obj(v: Value) -> Object {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn sign_then_verify() {
        let key = SigningKey::generate_p256();
        let raw = sign("kb+jwt", &Object::new(), &obj(json!({"a": 1})), &key).unwrap();
        let jws = Jws::parse(&raw).unwrap();
        jws.check_typ(&["kb+jwt"]).unwrap();
        jws.verify(&key.verifying_key()).unwrap();
        assert_eq!(jws.payload()["a"], 1);
    }

    #[test]
    fn typ_is_a_case_insensitive_media_type() {
        let key = SigningKey::generate_ed25519();
        let raw = sign("application/KB+JWT", &Object::new(), &Object::new(), &key).unwrap();
        let jws = Jws::parse(&raw).unwrap();
        jws.check_typ(&["kb+jwt"]).unwrap();
        assert!(jws.check_typ(&["kb+sd-jwt"]).is_err());
    }

    #[test]
    fn alg_mismatch_is_caught_before_the_signature() {
        let ed = SigningKey::generate_ed25519();
        let p = SigningKey::generate_p256();
        let raw = sign("kb+jwt", &Object::new(), &Object::new(), &ed).unwrap();
        let err = Jws::parse(&raw)
            .unwrap()
            .verify(&p.verifying_key())
            .unwrap_err();
        assert!(matches!(
            err,
            ErrorKind::AlgorithmMismatch { expected: "ES256", found: Some(ref f) } if f == "EdDSA"
        ));
    }

    #[test]
    fn crit_is_rejected() {
        let key = SigningKey::generate_p256();
        let mut raw_header = obj(json!({"crit": ["exp"]}));
        assert!(sign("kb+jwt", &raw_header, &Object::new(), &key).is_err());
        // Build the header by hand to get past `sign`'s own guard.
        raw_header.insert("alg".into(), "ES256".into());
        let input = format!(
            "{}.{}",
            B64.encode(serde_json::to_vec(&raw_header).unwrap()),
            B64.encode(b"{}")
        );
        let sig = key.sign(input.as_bytes()).unwrap();
        let raw = format!("{input}.{}", B64.encode(sig));
        assert_eq!(
            Jws::parse(&raw).unwrap().verify(&key.verifying_key()),
            Err(ErrorKind::UnsupportedHeader("crit".into()))
        );
    }

    #[test]
    fn jwt_shape_detection() {
        assert!(looks_like_jwt("a.b.c"));
        assert!(!looks_like_jwt("a.b"));
        assert!(!looks_like_jwt("a..c"));
        assert!(!looks_like_jwt("a.b.c.d"));
        assert!(!looks_like_jwt("WyJzYWx0Il0"));
    }
}
