//! JSON Pointers (RFC 6901), used to say which claims to conceal at
//! issuance and which to disclose at presentation.

use serde_json::Value;

use crate::error::ErrorKind;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum Segment {
    Key(String),
    Index(usize),
}

/// A parsed pointer whose segments have been resolved against a document,
/// so each segment is known to be an object key or an array index.
pub(crate) type Path = Vec<Segment>;

/// Parses `pointer` and resolves it against `doc`. The empty pointer (the
/// whole document) is rejected: neither concealing nor disclosing "the
/// document itself" means anything.
pub(crate) fn resolve(doc: &Value, pointer: &str) -> Result<Path, ErrorKind> {
    let invalid = || ErrorKind::InvalidPointer(pointer.to_owned());
    let rest = pointer.strip_prefix('/').ok_or_else(invalid)?;
    let mut path = Vec::new();
    let mut current = doc;
    for raw in rest.split('/') {
        if raw.contains('~') && !valid_escapes(raw) {
            return Err(invalid());
        }
        let token = raw.replace("~1", "/").replace("~0", "~");
        current = match current {
            Value::Object(map) => {
                let next = map.get(&token).ok_or_else(invalid)?;
                path.push(Segment::Key(token));
                next
            }
            Value::Array(items) => {
                // RFC 6901: decimal, no leading zeros, no "-".
                if token.is_empty() || (token.len() > 1 && token.starts_with('0')) {
                    return Err(invalid());
                }
                let index: usize = token.parse().map_err(|_| invalid())?;
                let next = items.get(index).ok_or_else(invalid)?;
                path.push(Segment::Index(index));
                next
            }
            _ => return Err(invalid()),
        };
    }
    Ok(path)
}

fn valid_escapes(token: &str) -> bool {
    let bytes = token.as_bytes();
    bytes
        .iter()
        .enumerate()
        .all(|(i, b)| *b != b'~' || matches!(bytes.get(i + 1), Some(b'0') | Some(b'1')))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn resolves_keys_indices_and_escapes() {
        let doc = json!({"a": [{"b/c": 1, "d~e": 2}]});
        assert_eq!(
            resolve(&doc, "/a/0/b~1c").unwrap(),
            vec![
                Segment::Key("a".into()),
                Segment::Index(0),
                Segment::Key("b/c".into())
            ]
        );
        assert!(resolve(&doc, "/a/0/d~0e").is_ok());
    }

    #[test]
    fn rejects_unresolvable_and_malformed_pointers() {
        let doc = json!({"a": [1, 2]});
        for p in ["", "a", "/b", "/a/2", "/a/01", "/a/-", "/a/0/x", "/a~2"] {
            assert!(resolve(&doc, p).is_err(), "{p}");
        }
    }
}
