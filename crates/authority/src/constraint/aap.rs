//! AAP's own constraint types (0004 "Mapping from v0"). Same semantics as
//! v0's `scope::matches`, rule by rule, on integer amounts and the
//! verifier's clock.

use crate::amount::Currency;
use crate::mandate::Action;
use crate::schema::{Fields, SchemaError};
use crate::time_window::TimeWindow;

use super::{violated, Failure};

pub(super) fn actions(allowed: &[String], a: &Action) -> Result<(), Failure> {
    if allowed.contains(&a.action) {
        Ok(())
    } else {
        Err(violated(format!("action {:?} is not allowed", a.action)))
    }
}

pub(super) fn resources(allowed: &[String], a: &Action) -> Result<(), Failure> {
    match &a.resource {
        Some(r) if allowed.contains(r) => Ok(()),
        Some(r) => Err(violated(format!("resource {r:?} is not allowed"))),
        None => Err(violated(
            "the mandate restricts resources, the action names none",
        )),
    }
}

pub(super) fn data_categories(allowed: &[String], a: &Action) -> Result<(), Failure> {
    match a
        .data_categories
        .iter()
        .flatten()
        .find(|c| !allowed.contains(c))
    {
        Some(c) => Err(violated(format!("data category {c:?} is not allowed"))),
        None => Ok(()),
    }
}

pub(super) fn time_windows(windows: &[TimeWindow], now: i64) -> Result<(), Failure> {
    if windows.iter().any(|w| w.contains(now)) {
        Ok(())
    } else {
        Err(violated(
            "the verifier's clock is outside every allowed time window",
        ))
    }
}

/// `aap.amount { max, currency }`: a per-action ceiling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmountCap {
    pub max: u64,
    pub currency: Currency,
}

impl AmountCap {
    pub(super) fn parse(f: &mut Fields<'_>) -> Result<Self, SchemaError> {
        Ok(AmountCap {
            max: f.uint("max")?,
            currency: f.currency("currency")?,
        })
    }

    /// An action without an amount moves no value and passes. An action
    /// *with* an amount under a mandate without any `aap.amount` is rejected
    /// in `OpenMandate::accepts` (v0 rule 3), not here.
    pub(super) fn evaluate(&self, a: &Action) -> Result<(), Failure> {
        match &a.amount {
            None => Ok(()),
            Some(amount) if amount.currency != self.currency => Err(violated(format!(
                "currency {} does not match the mandate's {}",
                amount.currency, self.currency
            ))),
            Some(amount) if amount.minor > self.max => Err(violated(format!(
                "amount {} exceeds the ceiling {}",
                amount.minor, self.max
            ))),
            Some(_) => Ok(()),
        }
    }

    pub(super) fn covers(&self, child: &AmountCap) -> bool {
        self.currency == child.currency && child.max <= self.max
    }
}

/// `aap.counterparties { allow?, deny? }`, at least one of the two. When
/// present, the action must name its counterparty: "deny X" cannot be
/// checked against an action that does not say who it is with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Counterparties {
    pub allow: Option<Vec<String>>,
    pub deny: Option<Vec<String>>,
}

impl Counterparties {
    pub(super) fn parse(f: &mut Fields<'_>) -> Result<Self, SchemaError> {
        let c = Counterparties {
            allow: f.opt_strings("allow")?,
            deny: f.opt_strings("deny")?,
        };
        if c.allow.is_none() && c.deny.is_none() {
            return Err(f.error("needs allow, deny, or both"));
        }
        Ok(c)
    }

    pub(super) fn evaluate(&self, a: &Action) -> Result<(), Failure> {
        let Some(cp) = &a.counterparty else {
            return Err(violated(
                "the mandate restricts counterparties, the action names none",
            ));
        };
        if self.deny.iter().flatten().any(|d| d == cp) {
            return Err(violated(format!("counterparty {cp:?} is denied")));
        }
        match &self.allow {
            Some(allow) if !allow.contains(cp) => {
                Err(violated(format!("counterparty {cp:?} is not allowed")))
            }
            _ => Ok(()),
        }
    }

    /// Child allow ⊆ parent allow (if the parent has one), child deny ⊇
    /// parent deny.
    pub(super) fn covers(&self, child: &Counterparties) -> bool {
        let allow_ok = match (&self.allow, &child.allow) {
            (None, _) => true,
            (Some(p), Some(c)) => c.iter().all(|x| p.contains(x)),
            (Some(_), None) => false,
        };
        let child_deny = child.deny.as_deref().unwrap_or_default();
        allow_ok && self.deny.iter().flatten().all(|d| child_deny.contains(d))
    }
}
