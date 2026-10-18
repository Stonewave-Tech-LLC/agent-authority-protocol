//! Issuance side of selective disclosure: turn a plain JSON object plus a
//! list of JSON Pointers into a payload with embedded digests and the
//! matching disclosures (RFC 9901 §4.2).
//!
//! Concealment runs deepest pointer first. That makes recursive disclosures
//! (§4.2.6) fall out naturally: concealing `/nationalities/0` and then
//! `/nationalities` produces a `nationalities` disclosure whose value
//! already contains the element digest. Decoys for a container are added
//! after its children are concealed and before the container itself is.

use rand::Rng as _;
use serde_json::{json, Value};

use crate::disclosure::{random_salt, Disclosure};
use crate::error::ErrorKind;
use crate::hash::SdAlg;
use crate::jws::Object;
use crate::pointer::{self, Path, Segment};

/// A JSON object and the parts of it that are to be selectively
/// disclosable. Used for the Issuer-signed JWT payload and for each Delegate
/// Payload of a KB-SD-JWT.
#[derive(Debug, Clone)]
pub struct SdPayload {
    claims: Object,
    concealed: Vec<String>,
    decoys: Vec<(String, usize)>,
}

enum Op {
    Conceal(Path),
    Decoys(Path, usize),
}

impl SdPayload {
    pub fn new(claims: Object) -> Self {
        SdPayload {
            claims,
            concealed: Vec::new(),
            decoys: Vec::new(),
        }
    }

    /// Makes the object property or array element at `pointer` selectively
    /// disclosable. Pointers refer to the plain input object; they are
    /// checked when the token is built.
    pub fn conceal(mut self, pointer: &str) -> Self {
        self.concealed.push(pointer.to_owned());
        self
    }

    /// Adds `count` decoy digests to the object (its `_sd`) or array at
    /// `pointer` (`""` is the top-level object).
    pub fn decoys(mut self, pointer: &str, count: usize) -> Self {
        self.decoys.push((pointer.to_owned(), count));
        self
    }

    pub(crate) fn claims(&self) -> &Object {
        &self.claims
    }

    pub(crate) fn build(self, alg: SdAlg) -> Result<(Object, Vec<Disclosure>), ErrorKind> {
        reject_reserved(&Value::Object(self.claims.clone()))?;
        if self.claims.contains_key("_sd_alg") {
            return Err(ErrorKind::ReservedName("_sd_alg".into()));
        }
        let mut doc = Value::Object(self.claims);
        let mut ops = Vec::new();
        for p in &self.concealed {
            let path = pointer::resolve(&doc, p)?;
            if ops
                .iter()
                .any(|op| matches!(op, Op::Conceal(existing) if *existing == path))
            {
                return Err(ErrorKind::InvalidPointer(p.clone()));
            }
            ops.push(Op::Conceal(path));
        }
        for (p, count) in &self.decoys {
            let path = if p.is_empty() {
                Vec::new()
            } else {
                pointer::resolve(&doc, p)?
            };
            match lookup(&doc, &path) {
                Value::Object(_) | Value::Array(_) => ops.push(Op::Decoys(path, *count)),
                _ => return Err(ErrorKind::InvalidPointer(p.clone())),
            }
        }
        // Deepest first; at equal depth decoys before concealment, so a
        // container gets its decoys before it is itself hidden.
        ops.sort_by_key(|op| match op {
            Op::Conceal(path) => (std::cmp::Reverse(path.len()), 1),
            Op::Decoys(path, _) => (std::cmp::Reverse(path.len()), 0),
        });

        let mut disclosures = Vec::new();
        for op in ops {
            match op {
                Op::Conceal(path) => disclosures.push(conceal_at(&mut doc, &path, alg)?),
                Op::Decoys(path, count) => add_decoys(lookup_mut(&mut doc, &path), count, alg),
            }
        }
        match doc {
            Value::Object(o) => Ok((o, disclosures)),
            _ => unreachable!("started as an object"),
        }
    }
}

/// RFC 9901 §4.1 rule 7: `_sd` and `...` are reserved for digests.
fn reject_reserved(value: &Value) -> Result<(), ErrorKind> {
    match value {
        Value::Object(o) => {
            for reserved in ["_sd", "..."] {
                if o.contains_key(reserved) {
                    return Err(ErrorKind::ReservedName(reserved.into()));
                }
            }
            o.values().try_for_each(reject_reserved)
        }
        Value::Array(a) => a.iter().try_for_each(reject_reserved),
        _ => Ok(()),
    }
}

fn lookup<'a>(doc: &'a Value, path: &[Segment]) -> &'a Value {
    path.iter().fold(doc, |v, seg| match seg {
        Segment::Key(k) => &v[k.as_str()],
        Segment::Index(i) => &v[*i],
    })
}

fn lookup_mut<'a>(doc: &'a mut Value, path: &[Segment]) -> &'a mut Value {
    path.iter().fold(doc, |v, seg| match seg {
        Segment::Key(k) => &mut v[k.as_str()],
        Segment::Index(i) => &mut v[*i],
    })
}

fn conceal_at(doc: &mut Value, path: &[Segment], alg: SdAlg) -> Result<Disclosure, ErrorKind> {
    let (last, parent_path) = path.split_last().expect("pointer is never empty");
    let parent = lookup_mut(doc, parent_path);
    match (last, parent) {
        (Segment::Key(name), Value::Object(obj)) => {
            let value = obj.remove(name).expect("resolved pointer");
            let disclosure = Disclosure::new_property(name, value);
            push_sd(obj, disclosure.digest(alg));
            Ok(disclosure)
        }
        (Segment::Index(i), Value::Array(items)) => {
            let value = std::mem::take(&mut items[*i]);
            let disclosure = Disclosure::new_element(value);
            items[*i] = json!({ "...": disclosure.digest(alg) });
            Ok(disclosure)
        }
        _ => unreachable!("pointer segments match the document they were resolved against"),
    }
}

/// Inserts into `_sd`, kept sorted so the array never reveals claim order
/// (RFC 9901 §4.2.4.1).
fn push_sd(obj: &mut Object, digest: String) {
    let sd = obj
        .entry("_sd")
        .or_insert_with(|| Value::Array(Vec::new()))
        .as_array_mut()
        .expect("_sd is only ever created here, as an array");
    let pos = sd
        .binary_search_by(|d| d.as_str().unwrap_or_default().cmp(digest.as_str()))
        .unwrap_or_else(|p| p);
    sd.insert(pos, Value::String(digest));
}

fn add_decoys(container: &mut Value, count: usize, alg: SdAlg) {
    let mut rng = rand::rngs::OsRng;
    for _ in 0..count {
        // §4.2.5: a digest over fresh random data, same hash as the rest.
        let decoy = alg.digest(&random_salt());
        match container {
            Value::Object(obj) => push_sd(obj, decoy),
            Value::Array(items) => {
                let at = rng.gen_range(0..=items.len());
                items.insert(at, json!({ "...": decoy }));
            }
            _ => unreachable!("checked when the op was created"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::process;

    fn obj(v: Value) -> Object {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn conceal_then_process_round_trips() {
        let input = json!({
            "sub": "user_42",
            "address": {"street": "Main St", "country": "US"},
            "nationalities": ["US", "DE"],
        });
        let (payload, disclosures) = SdPayload::new(obj(input.clone()))
            .conceal("/address/street")
            .conceal("/address")
            .conceal("/nationalities/1")
            .decoys("", 3)
            .decoys("/nationalities", 2)
            .decoys("/address", 1)
            .build(SdAlg::Sha256)
            .unwrap();
        assert_eq!(disclosures.len(), 3);
        assert!(!payload.contains_key("address"));
        assert_eq!(payload["_sd"].as_array().unwrap().len(), 4);
        assert_eq!(payload["nationalities"].as_array().unwrap().len(), 4);

        let processed = process(&payload, &disclosures, SdAlg::Sha256).unwrap();
        assert_eq!(Value::Object(processed.claims), input);
    }

    #[test]
    fn reserved_names_and_bad_pointers_are_rejected() {
        let bad = [
            SdPayload::new(obj(json!({"_sd": []}))),
            SdPayload::new(obj(json!({"a": [{"...": "x"}]}))),
            SdPayload::new(obj(json!({"_sd_alg": "sha-256"}))),
            SdPayload::new(obj(json!({"a": 1}))).conceal("/b"),
            SdPayload::new(obj(json!({"a": 1})))
                .conceal("/a")
                .conceal("/a"),
            SdPayload::new(obj(json!({"a": 1}))).decoys("/a", 1),
        ];
        for payload in bad {
            assert!(payload.build(SdAlg::Sha256).is_err());
        }
    }
}
