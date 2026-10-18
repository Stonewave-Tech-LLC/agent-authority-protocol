//! Cumulative evaluation (0004 V4) and the issuance-time `narrows` helper.
//!
//! The closed mandate must satisfy **every** open mandate in the chain, each
//! one judged on its own constraints and pre-set claims. A sub-delegation
//! can therefore never widen its parent, whatever it claims: the parent's
//! constraints are still evaluated. That is the security argument, and it
//! does not depend on [`narrows`].

use thiserror::Error;

use crate::constraint::{Constraint, Failure};
use crate::context::EvalEnv;
use crate::mandate::{ClosedContent, ClosedMandate, Family, OpenMandate};
use crate::names;

/// Why one open mandate does not accept the closed mandate.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Cause {
    #[error("the closed mandate is {closed:?}, the open mandate is {open:?}")]
    FamilyMismatch { open: Family, closed: Family },
    #[error("pre-set claim {claim:?} is missing or changed in the closed mandate")]
    Preset { claim: String },
    #[error(
        "the action carries an amount, but the mandate has no {}",
        names::aap::AMOUNT
    )]
    AmountWithoutCeiling,
    #[error("{type_name}: {failure}")]
    Constraint {
        type_name: &'static str,
        failure: Failure,
    },
}

/// The first open mandate (index into the slice) that rejects, and why.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("open mandate {link}: {cause}")]
pub struct ChainFailure {
    pub link: usize,
    pub cause: Cause,
}

impl OpenMandate {
    /// Does this open mandate, on its own, accept `closed`?
    pub fn accepts(&self, closed: &ClosedMandate, env: &EvalEnv<'_>) -> Result<(), Cause> {
        if self.family() != closed.family() {
            return Err(Cause::FamilyMismatch {
                open: self.family(),
                closed: closed.family(),
            });
        }
        for (claim, value) in self.presets() {
            if closed.claims().get(claim) != Some(value) {
                return Err(Cause::Preset {
                    claim: claim.clone(),
                });
            }
        }
        // v0 rule 3: money never passes through a mandate that never
        // mentioned money.
        if let ClosedContent::Action(a) = closed.content() {
            let has_ceiling = self
                .constraints()
                .iter()
                .any(|c| matches!(c, Constraint::Amount(_)));
            if a.amount.is_some() && !has_ceiling {
                return Err(Cause::AmountWithoutCeiling);
            }
        }
        for c in self.constraints() {
            c.evaluate(closed, env, self.ledger_key())
                .map_err(|failure| Cause::Constraint {
                    type_name: c.type_name(),
                    failure,
                })?;
        }
        Ok(())
    }
}

/// Every open mandate, root first, must accept the closed mandate. Returns
/// the first rejection in chain order, so the result is deterministic.
pub fn evaluate_chain(
    opens: &[OpenMandate],
    closed: &ClosedMandate,
    env: &EvalEnv<'_>,
) -> Result<(), ChainFailure> {
    for (link, open) in opens.iter().enumerate() {
        open.accepts(closed, env)
            .map_err(|cause| ChainFailure { link, cause })?;
    }
    Ok(())
}

/// Issuance-time check: is `child` a sub-delegation `parent` may sign?
///
/// `true` guarantees that everything `child` accepts, `parent` accepts
/// (for stateless constraints; budgets and recurrences are counted per
/// mandate, and the parent's own counter is still checked at verification),
/// and that `parent` permits one more level of delegation. Conservative:
/// `false` when that cannot be shown. The Issuer App and agents use it to
/// refuse impossible sub-delegations early. It is *not* part of the
/// security argument: the verifier evaluates every link anyway.
pub fn narrows(parent: &OpenMandate, child: &OpenMandate) -> bool {
    if parent.family() != child.family() || child.max_depth().saturating_add(1) > parent.max_depth()
    {
        return false;
    }
    if parent
        .presets()
        .iter()
        .any(|(k, v)| child.presets().get(k) != Some(v))
    {
        return false;
    }
    let has_amount = |m: &OpenMandate| {
        m.constraints()
            .iter()
            .any(|c| matches!(c, Constraint::Amount(_)))
    };
    // A ceiling in the child where the parent has none would let money
    // through that the parent rejects outright (v0 rule 3).
    if has_amount(child) && !has_amount(parent) {
        return false;
    }
    // Depth was compared above; every other parent constraint needs a child
    // constraint at least as strict.
    parent
        .constraints()
        .iter()
        .filter(|p| !matches!(p, Constraint::Delegation { .. }))
        .all(|p| {
            child
                .constraints()
                .iter()
                .any(|c| c.type_name() == p.type_name() && p.covers(c))
        })
}
