//! AAP v1 authorization on top of AP2's mandate model (0004 phase M3).
//!
//! `aap-sdjwt` proves a presentation is a correctly signed and chained
//! Delegate SD-JWT and hands over a [`aap_sdjwt::VerifiedChain`]. This crate
//! decides what that chain *permits*:
//!
//! - **Constraint types** ([`Constraint`]): AAP's `aap.actions`,
//!   `aap.resources`, `aap.amount`, `aap.counterparties`,
//!   `aap.data_categories`, `aap.time_windows`, `aap.delegation`, and AP2
//!   v0.2's checkout and payment constraints. Unknown types fail.
//! - **Cumulative evaluation** ([`evaluate_chain`]): the closed mandate must
//!   satisfy every open mandate in the chain, not only the last one.
//! - **The verifier** ([`Verifier`]): status, depth, cumulative evaluation,
//!   key-binding freshness and replay, and an AP2 Mandate Receipt for every
//!   outcome.
//! - **[`narrows`]**, for issuance only.
//!
//! # Why a separate crate
//!
//! 0004 puts this in `aap-core`, with AP2's types in an `aap-ap2` crate.
//! For now it lives here instead:
//!
//! - `aap-core` is v0 and is what the deployed verifier-service runs
//!   (device pairing). Until M5 removes v0, adding v1 there would mix two
//!   trust models in one crate and risk the deployed path.
//! - AP2's and AAP's constraints share one evaluator, one "unknown fails"
//!   rule and one applicability check. Splitting them across crates would
//!   need a plug-in registry, i.e. a way to add constraint types at run
//!   time, which is exactly what fail-closed evaluation should not have.
//!   They are separate modules (`constraint::aap`, `constraint::ap2`).
//!
//! At M5 this crate can become `aap-core`.
//!
//! # Names
//!
//! AAP type names are placeholders under [`names::AAP_NAMESPACE`] until the
//! namespace decision (0001).

#![forbid(unsafe_code)]

mod amount;
mod constraint;
mod context;
mod evaluate;
mod mandate;
pub mod names;
mod nonce;
mod receipt;
mod schema;
mod status;
mod time_window;
mod verifier;

pub use amount::{Amount, Currency};
pub use constraint::{
    AgentRecurrence, AmountCap, AmountRange, Budget, Constraint, ConstraintError, Counterparties,
    ExecutionDate, Failure, Frequency, LineItemRequirement, Merchant, PaymentInstrument, Pisp,
};
pub use context::{EvalEnv, LedgerError, Nonce, TransactionContext, Usage, UsageLedger};
pub use evaluate::{evaluate_chain, narrows, Cause, ChainFailure};
pub use mandate::{
    Action, Checkout, CheckoutMandate, ClosedContent, ClosedMandate, Family, MandateError,
    OpenMandate, PaymentMandate,
};
pub use nonce::{MemoryNonceStore, NonceStore, NonceStoreError};
pub use receipt::{ErrorCode, MandateReceipt};
pub use schema::SchemaError;
pub use status::{NoStatusList, StatusChecker, StatusError, TokenStatus};
pub use time_window::TimeWindow;
pub use verifier::{Authorized, Decision, Policy, Principal, Reason, RootPolicy, Verifier};
