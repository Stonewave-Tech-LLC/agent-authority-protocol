//! What the verifier knows about the transaction it is about to perform,
//! and the shared state some constraints need. Never taken from the
//! presentation: these are the verifier's own facts.

use aap_sdjwt::VerifyingKey;
use thiserror::Error;

use crate::mandate::Checkout;

/// How the final key binding's `nonce` is checked (0004 V5, open question
/// 2; 0005 per-class rules).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Nonce {
    /// The verifier issued this challenge for this transaction. Strongest;
    /// required for R3/R4 (0005).
    Challenge(String),
    /// Non-interactive APIs: the agent picks the nonce, and the verifier
    /// accepts it only once within the freshness window, through a
    /// [`crate::NonceStore`].
    AgentGenerated,
}

#[derive(Debug, Clone)]
pub struct TransactionContext {
    pub nonce: Nonce,
    /// The verifier's own merchant-signed checkout JWT, when it is the
    /// merchant. Trusted because the verifier made it; a `checkout_jwt`
    /// disclosed in the closed mandate must equal it.
    pub checkout_jwt: Option<String>,
    /// Lets the verifier trust a `checkout_jwt` it did not make, by checking
    /// the merchant's signature on it.
    pub merchant_key: Option<VerifyingKey>,
    /// The `checkout_hash` the verifier expects (AP2: the merchant MUST
    /// check it).
    pub expected_checkout_hash: Option<String>,
    /// The checkout a payment is for: a closed payment mandate's
    /// `transaction_id` must equal it. Required for payment mandates.
    pub expected_transaction_id: Option<String>,
    /// Hash of the open checkout mandate in the checkout's delegate chain,
    /// for `payment.reference`.
    pub open_checkout_hash: Option<String>,
}

impl TransactionContext {
    pub fn new(nonce: Nonce) -> Self {
        TransactionContext {
            nonce,
            checkout_jwt: None,
            merchant_key: None,
            expected_checkout_hash: None,
            expected_transaction_id: None,
            open_checkout_hash: None,
        }
    }
}

/// Past use of one open mandate, for `payment.budget` and
/// `payment.agent_recurrence`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Usage {
    /// Sum of previously accepted amounts, minor units of the budget's
    /// currency.
    pub total_minor: u64,
    pub uses: u64,
    /// Verifier time of the last accepted use.
    pub last_use: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("usage ledger: {0}")]
pub struct LedgerError(pub String);

/// The one place a shared budget lives (0005 P7, CG4). Keyed by the hash of
/// the JWT of the mandate that carries the constraint, so every
/// sub-delegation of a user-signed mandate draws on the same counter. An
/// unreachable ledger fails closed. Recording an accepted use is the
/// caller's job, with the keys from [`crate::Authorized::ledger_keys`].
pub trait UsageLedger {
    fn usage(&self, key: &str) -> Result<Usage, LedgerError>;
}

/// Everything a constraint may look at besides the closed mandate.
#[derive(Clone, Copy)]
pub struct EvalEnv<'a> {
    /// The verifier's clock, seconds since the epoch.
    pub now: i64,
    pub tx: &'a TransactionContext,
    pub ledger: Option<&'a dyn UsageLedger>,
    /// The checkout object, present only if its `checkout_jwt` is bound to
    /// the closed mandate *and* trusted (see `CheckoutMandate::bind`).
    pub checkout: Option<&'a Checkout>,
}
