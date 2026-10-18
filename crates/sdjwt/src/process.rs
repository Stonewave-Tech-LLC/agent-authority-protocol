//! RFC 9901 §7.1 steps 3–5: replace embedded digests with the values of the
//! disclosures that match them, drop undisclosed array elements and `_sd`
//! keys, and reject anything ambiguous:
//!
//! - a digest seen twice anywhere (payload or inside disclosures),
//! - the same disclosure sent twice,
//! - a disclosure that no digest references,
//! - a property disclosure found in an array or vice versa,
//! - a disclosed name that is `_sd`, `...`, or already present at its level,
//! - `_sd` that is not an array of strings, or `...` used anywhere other than
//!   as the single key of an array-element digest object.
//!
//! Alongside the processed payload it records, for every disclosure, the
//! path at which its value landed. The holder uses those paths to turn
//! "disclose /address/region" into a set of disclosures.

use std::collections::{HashMap, HashSet};

use serde_json::Value;

use crate::disclosure::Disclosure;
use crate::error::ErrorKind;
use crate::hash::SdAlg;
use crate::jws::Object;
use crate::pointer::{Path, Segment};

pub(crate) struct Processed {
    /// The Processed SD-JWT Payload, top-level `_sd_alg` removed.
    pub claims: Object,
    /// `paths[i]` is where `disclosures[i]`'s value sits in `claims`.
    pub paths: Vec<Path>,
}

pub(crate) fn process(
    payload: &Object,
    disclosures: &[Disclosure],
    alg: SdAlg,
) -> Result<Processed, ErrorKind> {
    let mut by_digest = HashMap::with_capacity(disclosures.len());
    for (i, d) in disclosures.iter().enumerate() {
        if by_digest.insert(d.digest(alg), i).is_some() {
            return Err(ErrorKind::DuplicateDisclosure);
        }
    }
    let mut walker = Walker {
        disclosures,
        by_digest,
        seen: HashSet::new(),
        paths: vec![None; disclosures.len()],
    };
    let mut claims = walker.object(payload, &mut Vec::new())?;
    claims.remove("_sd_alg");
    let paths = walker
        .paths
        .into_iter()
        .map(|p| p.ok_or(ErrorKind::UnreferencedDisclosure))
        .collect::<Result<_, _>>()?;
    Ok(Processed { claims, paths })
}

struct Walker<'a> {
    disclosures: &'a [Disclosure],
    by_digest: HashMap<String, usize>,
    seen: HashSet<String>,
    paths: Vec<Option<Path>>,
}

impl Walker<'_> {
    /// Records `digest` as seen and returns the matching disclosure, if any.
    fn lookup(&mut self, digest: &str) -> Result<Option<usize>, ErrorKind> {
        if !self.seen.insert(digest.to_owned()) {
            return Err(ErrorKind::DuplicateDigest(digest.to_owned()));
        }
        Ok(self.by_digest.get(digest).copied())
    }

    fn value(&mut self, value: &Value, path: &mut Path) -> Result<Value, ErrorKind> {
        Ok(match value {
            Value::Object(o) => Value::Object(self.object(o, path)?),
            Value::Array(a) => Value::Array(self.array(a, path)?),
            other => other.clone(),
        })
    }

    fn object(&mut self, obj: &Object, path: &mut Path) -> Result<Object, ErrorKind> {
        if obj.contains_key("...") {
            return Err(ErrorKind::ReservedName("...".into()));
        }
        let mut out = Object::new();
        for (name, value) in obj.iter().filter(|(k, _)| *k != "_sd") {
            path.push(Segment::Key(name.clone()));
            out.insert(name.clone(), self.value(value, path)?);
            path.pop();
        }
        let Some(sd) = obj.get("_sd") else {
            return Ok(out);
        };
        let digests = sd.as_array().ok_or(ErrorKind::InvalidClaim("_sd"))?;
        for digest in digests {
            let digest = digest.as_str().ok_or(ErrorKind::InvalidClaim("_sd"))?;
            let Some(i) = self.lookup(digest)? else {
                continue; // undisclosed claim or decoy
            };
            let disclosure = &self.disclosures[i];
            let name = disclosure.name().ok_or_else(|| {
                ErrorKind::InvalidDisclosure("array-element disclosure referenced from _sd".into())
            })?;
            if name == "_sd" || name == "..." {
                return Err(ErrorKind::ReservedName(name.to_owned()));
            }
            if out.contains_key(name) {
                return Err(ErrorKind::ClaimCollision(name.to_owned()));
            }
            path.push(Segment::Key(name.to_owned()));
            self.paths[i] = Some(path.clone());
            let value = self.value(disclosure.value(), path)?;
            path.pop();
            out.insert(name.to_owned(), value);
        }
        Ok(out)
    }

    fn array(&mut self, items: &[Value], path: &mut Path) -> Result<Vec<Value>, ErrorKind> {
        let mut out = Vec::with_capacity(items.len());
        for item in items {
            path.push(Segment::Index(out.len()));
            match element_digest(item)? {
                Some(digest) => {
                    if let Some(i) = self.lookup(digest)? {
                        let disclosure = &self.disclosures[i];
                        if disclosure.name().is_some() {
                            return Err(ErrorKind::InvalidDisclosure(
                                "property disclosure referenced from an array".into(),
                            ));
                        }
                        self.paths[i] = Some(path.clone());
                        out.push(self.value(disclosure.value(), path)?);
                    }
                }
                None => out.push(self.value(item, path)?),
            }
            path.pop();
        }
        Ok(out)
    }
}

/// `Some(digest)` for `{"...": "<digest>"}`. An object that has a `...` key
/// in any other shape is an error, not an ordinary object.
pub(crate) fn element_digest(item: &Value) -> Result<Option<&str>, ErrorKind> {
    let Some(obj) = item.as_object() else {
        return Ok(None);
    };
    match obj.get("...") {
        None => Ok(None),
        Some(Value::String(d)) if obj.len() == 1 => Ok(Some(d)),
        Some(_) => Err(ErrorKind::ReservedName("...".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn run(payload: Value, disclosures: &[&Disclosure]) -> Result<Processed, ErrorKind> {
        let owned: Vec<Disclosure> = disclosures.iter().map(|d| (*d).clone()).collect();
        process(payload.as_object().unwrap(), &owned, SdAlg::Sha256)
    }

    fn digest(d: &Disclosure) -> String {
        d.digest(SdAlg::Sha256)
    }

    #[test]
    fn recursive_disclosures_and_paths() {
        let de = Disclosure::new_element(json!("DE"));
        let fr = Disclosure::new_element(json!("FR"));
        let nat = Disclosure::new_property(
            "nationalities",
            json!([{"...": digest(&de)}, {"...": digest(&fr)}]),
        );
        let payload = json!({"_sd": [digest(&nat), "decoy"], "_sd_alg": "sha-256", "sub": "x"});

        let p = run(payload.clone(), &[&nat, &fr]).unwrap();
        assert_eq!(
            Value::Object(p.claims),
            json!({"sub": "x", "nationalities": ["FR"]})
        );
        assert_eq!(p.paths[0], vec![Segment::Key("nationalities".into())]);
        assert_eq!(
            p.paths[1],
            vec![Segment::Key("nationalities".into()), Segment::Index(0)]
        );

        // FR without its parent cannot connect to the payload.
        assert_eq!(
            run(payload, &[&fr]).err(),
            Some(ErrorKind::UnreferencedDisclosure)
        );
    }

    #[test]
    fn rejects_ambiguity() {
        let a = Disclosure::new_property("a", json!(1));
        let el = Disclosure::new_element(json!(1));
        let cases: Vec<(Value, Vec<&Disclosure>, ErrorKind)> = vec![
            (
                json!({"_sd": [digest(&a)], "a": 2}),
                vec![&a],
                ErrorKind::ClaimCollision("a".into()),
            ),
            (
                json!({"_sd": [digest(&a)], "x": {"_sd": [digest(&a)]}}),
                vec![&a],
                ErrorKind::DuplicateDigest(digest(&a)),
            ),
            (
                json!({"_sd": [digest(&a)]}),
                vec![&a, &a],
                ErrorKind::DuplicateDisclosure,
            ),
            (
                json!({"_sd": [digest(&el)]}),
                vec![&el],
                ErrorKind::InvalidDisclosure("array-element disclosure referenced from _sd".into()),
            ),
            (
                json!({"x": [{"...": digest(&a)}]}),
                vec![&a],
                ErrorKind::InvalidDisclosure("property disclosure referenced from an array".into()),
            ),
            (
                json!({"_sd": "nope"}),
                vec![],
                ErrorKind::InvalidClaim("_sd"),
            ),
            (
                json!({"x": [{"...": "d", "y": 1}]}),
                vec![],
                ErrorKind::ReservedName("...".into()),
            ),
            (
                json!({"...": "d"}),
                vec![],
                ErrorKind::ReservedName("...".into()),
            ),
        ];
        for (payload, discs, expected) in cases {
            assert_eq!(
                run(payload.clone(), &discs).err(),
                Some(expected),
                "{payload}"
            );
        }

        let sd = Disclosure::new_property("_sd", json!([]));
        assert_eq!(
            run(json!({"_sd": [digest(&sd)]}), &[&sd]).err(),
            Some(ErrorKind::ReservedName("_sd".into()))
        );
    }
}
