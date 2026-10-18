//! Constraint types: parsing, evaluation against a closed mandate, and the
//! per-type "at least as strict" relation used by [`crate::narrows`].
//!
//! Rules every constraint follows:
//!
//! - **Unknown types fail** (AP2 "Verification and Processing Rules" 3;
//!   0004 V4). So do unknown members of a known type (see `schema`).
//! - **Evaluation is pure** apart from the verifier's clock and, for
//!   `payment.budget` / `payment.agent_recurrence`, the usage ledger.
//! - **A constraint applies to one mandate family.** AAP constraints
//!   constrain `aap.action.1`, `checkout.*` the checkout mandate,
//!   `payment.*` the payment mandate. `aap.delegation` is structural and fits
//!   every family. A constraint in the wrong family is rejected at parse
//!   time, never skipped.

mod aap;
mod ap2;

pub use self::aap::{AmountCap, Counterparties};
pub use self::ap2::{
    AgentRecurrence, AmountRange, Budget, ExecutionDate, Frequency, LineItemRequirement, Merchant,
    PaymentInstrument, Pisp,
};

use serde_json::Value;
use thiserror::Error;

use crate::context::EvalEnv;
use crate::mandate::{ClosedContent, ClosedMandate, Family};
use crate::names;
use crate::schema::{Fields, SchemaError};
use crate::time_window::TimeWindow;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Constraint {
    /// `aap.actions { allowed }`: the action must be listed.
    Actions(Vec<String>),
    /// `aap.resources { allowed }`: the action must name a listed resource.
    Resources(Vec<String>),
    /// `aap.amount { max, currency }`.
    Amount(AmountCap),
    /// `aap.counterparties { allow?, deny? }`.
    Counterparties(Counterparties),
    /// `aap.data_categories { allowed }`: requested categories ⊆ allowed.
    DataCategories(Vec<String>),
    /// `aap.time_windows { windows }`: the verifier's clock is in one.
    TimeWindows(Vec<TimeWindow>),
    /// `aap.delegation { max_depth }`: how many further open mandates may
    /// follow this one. Absent means none (0004 V3).
    Delegation { max_depth: u32 },

    /// `checkout.allowed_merchants { allowed }`.
    AllowedMerchants(Vec<Merchant>),
    /// `checkout.line_items { items }`.
    LineItems(Vec<LineItemRequirement>),
    /// `payment.amount_range { currency, max, min? }`.
    AmountRange(AmountRange),
    /// `payment.allowed_payees { allowed }`.
    AllowedPayees(Vec<Merchant>),
    /// `payment.allowed_payment_instruments { allowed }`.
    AllowedPaymentInstruments(Vec<PaymentInstrument>),
    /// `payment.allowed_pisps { allowed }`.
    AllowedPisps(Vec<Pisp>),
    /// `payment.budget { max, currency }`, stateful.
    Budget(Budget),
    /// `payment.agent_recurrence { frequency, max_occurrences? }`, stateful.
    AgentRecurrence(AgentRecurrence),
    /// `payment.execution_date { not_before?, not_after? }`.
    ExecutionDate(ExecutionDate),
    /// `payment.reference { conditional_transaction_id }`.
    Reference(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ConstraintError {
    #[error("unknown constraint type {0:?}")]
    Unknown(String),
    #[error("{0}")]
    Malformed(#[from] SchemaError),
}

/// Why a constraint does not accept a closed mandate.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Failure {
    /// The closed mandate is outside the constraint. AP2 `invalid_mandate`.
    #[error("{0}")]
    Violated(String),
    /// The verifier cannot decide (no ledger, no trusted checkout, ...).
    /// AP2 `unresolved_constraint`; still a rejection.
    #[error("cannot evaluate: {0}")]
    Unresolved(String),
}

pub(crate) fn violated(message: impl Into<String>) -> Failure {
    Failure::Violated(message.into())
}

pub(crate) fn unresolved(message: impl Into<String>) -> Failure {
    Failure::Unresolved(message.into())
}

impl Constraint {
    pub fn parse(value: &Value) -> Result<Self, ConstraintError> {
        let type_name = value
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| SchemaError::new("constraint", "missing string member \"type\""))?;
        let mut f = Fields::new(value, type_name)?;
        f.allow(&["type"]);
        let constraint = match type_name {
            names::aap::ACTIONS => Constraint::Actions(f.strings("allowed")?),
            names::aap::RESOURCES => Constraint::Resources(f.strings("allowed")?),
            names::aap::DATA_CATEGORIES => Constraint::DataCategories(f.strings("allowed")?),
            names::aap::AMOUNT => Constraint::Amount(AmountCap::parse(&mut f)?),
            names::aap::COUNTERPARTIES => {
                Constraint::Counterparties(Counterparties::parse(&mut f)?)
            }
            names::aap::TIME_WINDOWS => {
                Constraint::TimeWindows(f.array("windows", TimeWindow::parse)?)
            }
            names::aap::DELEGATION => {
                let depth = f.uint("max_depth")?;
                let max_depth =
                    u32::try_from(depth).map_err(|_| f.error("max_depth is too large"))?;
                Constraint::Delegation { max_depth }
            }
            names::ap2::ALLOWED_MERCHANTS => {
                Constraint::AllowedMerchants(f.array("allowed", Merchant::parse)?)
            }
            names::ap2::LINE_ITEMS => {
                Constraint::LineItems(f.array("items", LineItemRequirement::parse)?)
            }
            names::ap2::AMOUNT_RANGE => Constraint::AmountRange(AmountRange::parse(&mut f)?),
            names::ap2::ALLOWED_PAYEES => {
                Constraint::AllowedPayees(f.array("allowed", Merchant::parse)?)
            }
            names::ap2::ALLOWED_PAYMENT_INSTRUMENTS => {
                Constraint::AllowedPaymentInstruments(f.array("allowed", PaymentInstrument::parse)?)
            }
            names::ap2::ALLOWED_PISPS => Constraint::AllowedPisps(f.array("allowed", Pisp::parse)?),
            names::ap2::BUDGET => Constraint::Budget(Budget::parse(&mut f)?),
            names::ap2::AGENT_RECURRENCE => {
                Constraint::AgentRecurrence(AgentRecurrence::parse(&mut f)?)
            }
            names::ap2::EXECUTION_DATE => Constraint::ExecutionDate(ExecutionDate::parse(&mut f)?),
            names::ap2::REFERENCE => Constraint::Reference(f.string("conditional_transaction_id")?),
            other => return Err(ConstraintError::Unknown(other.to_owned())),
        };
        f.finish()?;
        Ok(constraint)
    }

    pub fn type_name(&self) -> &'static str {
        use names::{aap, ap2};
        match self {
            Constraint::Actions(_) => aap::ACTIONS,
            Constraint::Resources(_) => aap::RESOURCES,
            Constraint::Amount(_) => aap::AMOUNT,
            Constraint::Counterparties(_) => aap::COUNTERPARTIES,
            Constraint::DataCategories(_) => aap::DATA_CATEGORIES,
            Constraint::TimeWindows(_) => aap::TIME_WINDOWS,
            Constraint::Delegation { .. } => aap::DELEGATION,
            Constraint::AllowedMerchants(_) => ap2::ALLOWED_MERCHANTS,
            Constraint::LineItems(_) => ap2::LINE_ITEMS,
            Constraint::AmountRange(_) => ap2::AMOUNT_RANGE,
            Constraint::AllowedPayees(_) => ap2::ALLOWED_PAYEES,
            Constraint::AllowedPaymentInstruments(_) => ap2::ALLOWED_PAYMENT_INSTRUMENTS,
            Constraint::AllowedPisps(_) => ap2::ALLOWED_PISPS,
            Constraint::Budget(_) => ap2::BUDGET,
            Constraint::AgentRecurrence(_) => ap2::AGENT_RECURRENCE,
            Constraint::ExecutionDate(_) => ap2::EXECUTION_DATE,
            Constraint::Reference(_) => ap2::REFERENCE,
        }
    }

    /// The mandate family this constraint constrains; `None` for
    /// `aap.delegation`, which fits all.
    pub fn family(&self) -> Option<Family> {
        match self {
            Constraint::Delegation { .. } => None,
            Constraint::Actions(_)
            | Constraint::Resources(_)
            | Constraint::Amount(_)
            | Constraint::Counterparties(_)
            | Constraint::DataCategories(_)
            | Constraint::TimeWindows(_) => Some(Family::Authority),
            Constraint::AllowedMerchants(_) | Constraint::LineItems(_) => Some(Family::Checkout),
            _ => Some(Family::Payment),
        }
    }

    /// Does this constraint accept `closed`? `ledger_key` names the counter
    /// of the mandate this constraint sits in (stateful constraints only).
    pub fn evaluate(
        &self,
        closed: &ClosedMandate,
        env: &EvalEnv<'_>,
        ledger_key: &str,
    ) -> Result<(), Failure> {
        match (self, closed.content()) {
            (Constraint::Delegation { .. }, _) => Ok(()),
            (Constraint::Actions(allowed), ClosedContent::Action(a)) => aap::actions(allowed, a),
            (Constraint::Resources(allowed), ClosedContent::Action(a)) => {
                aap::resources(allowed, a)
            }
            (Constraint::Amount(cap), ClosedContent::Action(a)) => cap.evaluate(a),
            (Constraint::Counterparties(c), ClosedContent::Action(a)) => c.evaluate(a),
            (Constraint::DataCategories(allowed), ClosedContent::Action(a)) => {
                aap::data_categories(allowed, a)
            }
            (Constraint::TimeWindows(windows), ClosedContent::Action(_)) => {
                aap::time_windows(windows, env.now)
            }
            (Constraint::AllowedMerchants(allowed), ClosedContent::Checkout(_)) => {
                ap2::allowed_merchants(allowed, env)
            }
            (Constraint::LineItems(items), ClosedContent::Checkout(_)) => {
                ap2::line_items(items, env)
            }
            (Constraint::AmountRange(r), ClosedContent::Payment(p)) => r.evaluate(p),
            (Constraint::AllowedPayees(allowed), ClosedContent::Payment(p)) => {
                ap2::allowed_payees(allowed, p)
            }
            (Constraint::AllowedPaymentInstruments(allowed), ClosedContent::Payment(p)) => {
                ap2::allowed_instruments(allowed, p)
            }
            (Constraint::AllowedPisps(allowed), ClosedContent::Payment(p)) => {
                ap2::allowed_pisps(allowed, p)
            }
            (Constraint::Budget(b), ClosedContent::Payment(p)) => b.evaluate(p, env, ledger_key),
            (Constraint::AgentRecurrence(r), ClosedContent::Payment(_)) => {
                r.evaluate(env, ledger_key)
            }
            (Constraint::ExecutionDate(d), ClosedContent::Payment(p)) => d.evaluate(p, env.now),
            (Constraint::Reference(id), ClosedContent::Payment(_)) => ap2::reference(id, env),
            (c, _) => Err(unresolved(format!(
                "{} does not apply to {}",
                c.type_name(),
                closed.family().closed_vct()
            ))),
        }
    }

    /// Is `child` (a constraint of the same type) at least as strict as
    /// `self`, i.e. does everything `child` accepts satisfy `self` too?
    /// Conservative: `false` whenever that cannot be shown cheaply.
    pub fn covers(&self, child: &Constraint) -> bool {
        use Constraint as C;
        match (self, child) {
            (C::Actions(p), C::Actions(c))
            | (C::Resources(p), C::Resources(c))
            | (C::DataCategories(p), C::DataCategories(c)) => c.iter().all(|x| p.contains(x)),
            (C::Amount(p), C::Amount(c)) => p.covers(c),
            (C::Counterparties(p), C::Counterparties(c)) => p.covers(c),
            (C::TimeWindows(p), C::TimeWindows(c)) => c.iter().all(|w| w.covered_by(p)),
            // Depth is structural; `narrows` checks it on the mandates.
            (C::Delegation { .. }, C::Delegation { .. }) => true,
            (C::AllowedMerchants(p), C::AllowedMerchants(c))
            | (C::AllowedPayees(p), C::AllowedPayees(c)) => {
                c.iter().all(|m| p.iter().any(|x| x.id == m.id))
            }
            // Max-flow matching is not monotone in any simple way; only an
            // identical requirement list is known to be no wider.
            (C::LineItems(p), C::LineItems(c)) => p == c,
            (C::AmountRange(p), C::AmountRange(c)) => p.covers(c),
            (C::AllowedPaymentInstruments(p), C::AllowedPaymentInstruments(c)) => {
                c.iter().all(|i| p.iter().any(|x| x.id == i.id))
            }
            (C::AllowedPisps(p), C::AllowedPisps(c)) => c.iter().all(|i| p.contains(i)),
            (C::Budget(p), C::Budget(c)) => p.currency == c.currency && c.max <= p.max,
            (C::AgentRecurrence(p), C::AgentRecurrence(c)) => p.covers(c),
            (C::ExecutionDate(p), C::ExecutionDate(c)) => p.covers(c),
            (C::Reference(p), C::Reference(c)) => p == c,
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn unknown_types_and_members_fail() {
        assert_eq!(
            Constraint::parse(&json!({"type": "aap.rate", "max_count": 1})),
            Err(ConstraintError::Unknown("aap.rate".into()))
        );
        assert!(matches!(
            Constraint::parse(&json!({"type": "aap.actions", "allowed": ["a"], "except": ["b"]})),
            Err(ConstraintError::Malformed(_))
        ));
        assert!(Constraint::parse(&json!({"allowed": ["a"]})).is_err());
    }

    #[test]
    fn every_type_round_trips_its_name() {
        let samples = [
            json!({"type": "aap.actions", "allowed": ["a"]}),
            json!({"type": "aap.resources", "allowed": ["r"]}),
            json!({"type": "aap.amount", "max": 100, "currency": "EUR"}),
            json!({"type": "aap.counterparties", "deny": ["x"]}),
            json!({"type": "aap.data_categories", "allowed": ["balance"]}),
            json!({"type": "aap.time_windows", "windows": [
                {"days": ["mon"], "start": "09:00", "end": "17:00", "timezone": "UTC"}]}),
            json!({"type": "aap.delegation", "max_depth": 1}),
            json!({"type": "checkout.allowed_merchants", "allowed": [{"id": "m", "name": "M"}]}),
            json!({"type": "checkout.line_items", "items": [
                {"id": "l", "quantity": 1, "acceptable_items": [{"id": "s", "title": "S"}]}]}),
            json!({"type": "payment.amount_range", "currency": "USD", "max": 5, "min": 1}),
            json!({"type": "payment.allowed_payees", "allowed": [{"id": "m", "name": "M"}]}),
            json!({"type": "payment.allowed_payment_instruments", "allowed": [{"id": "i", "type": "card"}]}),
            json!({"type": "payment.allowed_pisps", "allowed": [
                {"legal_name": "L", "brand_name": "B", "domain_name": "d.example"}]}),
            json!({"type": "payment.budget", "max": 100000, "currency": "USD"}),
            json!({"type": "payment.agent_recurrence", "frequency": "MONTHLY", "max_occurrences": 12}),
            json!({"type": "payment.execution_date", "not_after": "2026-12-31"}),
            json!({"type": "payment.reference", "conditional_transaction_id": "abc"}),
        ];
        for s in samples {
            let c = Constraint::parse(&s).unwrap_or_else(|e| panic!("{s}: {e}"));
            assert_eq!(c.type_name(), s["type"], "{s}");
        }
    }
}
