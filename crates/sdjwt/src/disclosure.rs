//! Disclosures (RFC 9901 §4.2): base64url of `[salt, name, value]` for an
//! object property or `[salt, value]` for an array element. The digest is
//! taken over the encoded string itself, so the encoded form is kept
//! verbatim and never re-serialized.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine as _};
use rand::RngCore as _;
use serde_json::Value;

use crate::error::ErrorKind;
use crate::hash::SdAlg;

/// 128 bits, the minimum RFC 9901 §9.3 recommends.
const SALT_BYTES: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Disclosure {
    encoded: String,
    salt: String,
    name: Option<String>,
    value: Value,
}

pub(crate) fn random_salt() -> String {
    let mut bytes = [0u8; SALT_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    B64.encode(bytes)
}

impl Disclosure {
    pub fn parse(encoded: &str) -> Result<Self, ErrorKind> {
        let bytes = B64.decode(encoded).map_err(|_| ErrorKind::Base64)?;
        let array: Vec<Value> = match serde_json::from_slice(&bytes) {
            Ok(Value::Array(a)) => a,
            Ok(_) => return Err(ErrorKind::InvalidDisclosure("not a JSON array".into())),
            Err(e) => return Err(ErrorKind::InvalidDisclosure(e.to_string())),
        };
        let mut items = array.into_iter();
        let (salt, name, value) = match (items.next(), items.next(), items.next(), items.next()) {
            (Some(Value::String(salt)), Some(value), None, None) => (salt, None, value),
            (Some(Value::String(salt)), Some(Value::String(name)), Some(value), None) => {
                (salt, Some(name), value)
            }
            _ => {
                return Err(ErrorKind::InvalidDisclosure(
                    "expected [salt, value] or [salt, name, value] with string salt and name"
                        .into(),
                ))
            }
        };
        Ok(Disclosure {
            encoded: encoded.to_owned(),
            salt,
            name,
            value,
        })
    }

    fn create(name: Option<&str>, value: Value) -> Self {
        let salt = random_salt();
        let array = match name {
            Some(n) => Value::Array(vec![salt.clone().into(), n.into(), value.clone()]),
            None => Value::Array(vec![salt.clone().into(), value.clone()]),
        };
        let encoded = B64.encode(array.to_string());
        Disclosure {
            encoded,
            salt,
            name: name.map(str::to_owned),
            value,
        }
    }

    pub(crate) fn new_property(name: &str, value: Value) -> Self {
        Self::create(Some(name), value)
    }

    pub(crate) fn new_element(value: Value) -> Self {
        Self::create(None, value)
    }

    /// The disclosure exactly as transmitted.
    pub fn encoded(&self) -> &str {
        &self.encoded
    }

    pub fn salt(&self) -> &str {
        &self.salt
    }

    /// The claim name for an object-property disclosure, `None` for an
    /// array-element disclosure.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    pub fn value(&self) -> &Value {
        &self.value
    }

    pub fn digest(&self, alg: SdAlg) -> String {
        alg.digest(&self.encoded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rfc9901_property_disclosure_and_its_encoding_variants() {
        // §4.2.1: different JSON encodings of the same claim all parse to
        // the same value, but each has its own digest.
        let variants = [
            "WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0",
            "WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNXHUwMGY2Yml1cyJd",
            "WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsImZhbWlseV9uYW1lIiwiTcO2Yml1cyJd",
            "WwoiXzI2YmM0TFQtYWM2cTJLSTZjQlc1ZXMiLAoiZmFtaWx5X25hbWUiLAoiTcO2Yml1cyIKXQ",
        ];
        for v in variants {
            let d = Disclosure::parse(v).unwrap();
            assert_eq!(d.salt(), "_26bc4LT-ac6q2KI6cBW5es");
            assert_eq!(d.name(), Some("family_name"));
            assert_eq!(d.value(), &json!("Möbius"));
        }
        assert_eq!(
            Disclosure::parse(variants[0])
                .unwrap()
                .digest(SdAlg::Sha256),
            "X9yH0Ajrdm1Oij4tWso9UzzKJvPoDxwmuEcO3XAdRC0"
        );
    }

    #[test]
    fn rfc9901_array_element_disclosure() {
        // §4.2.2 / §4.2.4.2: ["lklxF5jMYlGTPUovMNIvCA", "FR"].
        let d = Disclosure::parse("WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIkZSIl0").unwrap();
        assert_eq!(d.name(), None);
        assert_eq!(d.value(), &json!("FR"));
        assert_eq!(
            d.digest(SdAlg::Sha256),
            "w0I8EKcdCtUPkGCNUrfwVp2xEgNjtoIDlOxc9-PlOhs"
        );
    }

    #[test]
    fn malformed_disclosures_are_rejected() {
        for json in [
            r#"["salt"]"#,
            r#"["salt", "name", "value", "extra"]"#,
            r#"[1, "value"]"#,
            r#"["salt", 1, "value"]"#,
            r#"{"salt": "x"}"#,
        ] {
            let encoded = B64.encode(json);
            assert!(Disclosure::parse(&encoded).is_err(), "{json}");
        }
        assert_eq!(Disclosure::parse("a=="), Err(ErrorKind::Base64));
    }

    #[test]
    fn created_disclosures_have_128_bit_salts_and_round_trip() {
        let d = Disclosure::new_property("given_name", json!("Alice"));
        assert_eq!(B64.decode(d.salt()).unwrap().len(), 16);
        assert_eq!(Disclosure::parse(d.encoded()).unwrap(), d);
        assert_ne!(d.salt(), Disclosure::new_element(json!(1)).salt());
    }
}
