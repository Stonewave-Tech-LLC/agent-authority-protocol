//! Strict reading of mandate JSON. A constraint or closed mandate with a
//! field this crate does not know is rejected, not ignored: an unknown field
//! may be a restriction the issuer meant, and ignoring it would widen the
//! mandate (fail closed, like unknown constraint types).

use serde_json::{Map, Value};
use thiserror::Error;

use crate::amount::{Amount, Currency};

pub(crate) type Object = Map<String, Value>;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{context}: {message}")]
pub struct SchemaError {
    pub context: String,
    pub message: String,
}

impl SchemaError {
    pub(crate) fn new(context: &str, message: impl Into<String>) -> Self {
        SchemaError {
            context: context.to_owned(),
            message: message.into(),
        }
    }
}

/// Reads the members of one JSON object, remembering which were read, so
/// that [`Fields::finish`] can reject everything else.
pub(crate) struct Fields<'a> {
    context: &'a str,
    object: &'a Object,
    read: Vec<&'a str>,
}

impl<'a> Fields<'a> {
    pub(crate) fn new(value: &'a Value, context: &'a str) -> Result<Self, SchemaError> {
        let object = value
            .as_object()
            .ok_or_else(|| SchemaError::new(context, "not a JSON object"))?;
        Ok(Fields {
            context,
            object,
            read: Vec::new(),
        })
    }

    pub(crate) fn error(&self, message: impl Into<String>) -> SchemaError {
        SchemaError::new(self.context, message)
    }

    /// Marks `names` as known without reading them.
    pub(crate) fn allow(&mut self, names: &[&'a str]) {
        self.read.extend_from_slice(names);
    }

    pub(crate) fn opt(&mut self, name: &'a str) -> Option<&'a Value> {
        self.read.push(name);
        self.object.get(name)
    }

    pub(crate) fn req(&mut self, name: &'a str) -> Result<&'a Value, SchemaError> {
        self.opt(name)
            .ok_or_else(|| self.error(format!("missing {name:?}")))
    }

    pub(crate) fn string(&mut self, name: &'a str) -> Result<String, SchemaError> {
        let v = self.req(name)?;
        string(v).ok_or_else(|| self.error(format!("{name:?} must be a non-empty string")))
    }

    pub(crate) fn opt_string(&mut self, name: &'a str) -> Result<Option<String>, SchemaError> {
        match self.opt(name) {
            None => Ok(None),
            Some(v) => string(v)
                .map(Some)
                .ok_or_else(|| self.error(format!("{name:?} must be a non-empty string"))),
        }
    }

    pub(crate) fn uint(&mut self, name: &'a str) -> Result<u64, SchemaError> {
        let v = self.req(name)?;
        uint(v).ok_or_else(|| self.error(format!("{name:?} must be a non-negative integer")))
    }

    pub(crate) fn opt_uint(&mut self, name: &'a str) -> Result<Option<u64>, SchemaError> {
        match self.opt(name) {
            None => Ok(None),
            Some(v) => uint(v)
                .map(Some)
                .ok_or_else(|| self.error(format!("{name:?} must be a non-negative integer"))),
        }
    }

    /// A non-empty array of non-empty strings, without duplicates.
    pub(crate) fn strings(&mut self, name: &'a str) -> Result<Vec<String>, SchemaError> {
        let v = self.req(name)?;
        strings(v).ok_or_else(|| {
            self.error(format!(
                "{name:?} must be a non-empty array of distinct non-empty strings"
            ))
        })
    }

    pub(crate) fn opt_strings(
        &mut self,
        name: &'a str,
    ) -> Result<Option<Vec<String>>, SchemaError> {
        match self.opt(name) {
            None => Ok(None),
            Some(v) => strings(v).map(Some).ok_or_else(|| {
                self.error(format!(
                    "{name:?} must be a non-empty array of distinct non-empty strings"
                ))
            }),
        }
    }

    pub(crate) fn currency(&mut self, name: &'a str) -> Result<Currency, SchemaError> {
        let s = self.string(name)?;
        Currency::parse(&s).map_err(|m| self.error(m))
    }

    /// A non-empty array, each element read by `item`.
    pub(crate) fn array<T>(
        &mut self,
        name: &'a str,
        item: impl Fn(&Value) -> Result<T, SchemaError>,
    ) -> Result<Vec<T>, SchemaError> {
        let items = self
            .req(name)?
            .as_array()
            .ok_or_else(|| self.error(format!("{name:?} must be an array")))?;
        if items.is_empty() {
            return Err(self.error(format!(
                "{name:?} has no (disclosed) elements, so nothing is allowed"
            )));
        }
        items.iter().map(item).collect()
    }

    pub(crate) fn finish(self) -> Result<(), SchemaError> {
        match self
            .object
            .keys()
            .find(|k| !self.read.contains(&k.as_str()))
        {
            Some(unknown) => Err(SchemaError::new(
                self.context,
                format!("unknown member {unknown:?}"),
            )),
            None => Ok(()),
        }
    }
}

fn string(v: &Value) -> Option<String> {
    v.as_str().filter(|s| !s.is_empty()).map(str::to_owned)
}

/// An integer JSON number that is not negative. `100.0`, `1e3` and
/// `-1` are all rejected: amounts are integer minor units (0004).
pub(crate) fn uint(v: &Value) -> Option<u64> {
    match v {
        Value::Number(n) => n.as_u64(),
        _ => None,
    }
}

fn strings(v: &Value) -> Option<Vec<String>> {
    let items = v.as_array().filter(|a| !a.is_empty())?;
    let mut out: Vec<String> = Vec::with_capacity(items.len());
    for item in items {
        let s = string(item)?;
        if out.contains(&s) {
            return None;
        }
        out.push(s);
    }
    Some(out)
}

/// AP2's `Amount` object: `{"amount": <integer minor units>, "currency":
/// "<ISO 4217>"}`. Also the shape of the amount in `aap.action.1`.
pub(crate) fn amount(v: &Value, context: &str) -> Result<Amount, SchemaError> {
    let mut f = Fields::new(v, context)?;
    let minor = f.uint("amount")?;
    let currency = f.currency("currency")?;
    f.finish()?;
    Ok(Amount { minor, currency })
}
