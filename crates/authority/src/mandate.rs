//! Mandate content: the open mandates of a chain and the closed mandate at
//! its end, parsed from the claims of a verified link.
//!
//! Three families, each an open type and the closed type it is closed into:
//!
//! | family | open | closed |
//! |---|---|---|
//! | Authority (AAP) | `aap.authority.open.1` | `aap.action.1` |
//! | Checkout (AP2) | `mandate.checkout.open.1` | `mandate.checkout.1` |
//! | Payment (AP2) | `mandate.payment.open.1` | `mandate.payment.1` |
//!
//! A chain stays in one family. Every claim of an open mandate that is not
//! structural (`vct`, `constraints`, `cnf`, validity, status, informational
//! notes) is a *pre-set claim*: the closed mandate must carry it unchanged
//! (AP2 "Verification and Processing Rules" 2).

use aap_sdjwt::{verify_jwt, SdAlg};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine as _};
use serde_json::Value;
use thiserror::Error;

use crate::amount::Amount;
use crate::constraint::{
    unresolved, violated, Constraint, ConstraintError, Failure, Merchant, PaymentInstrument, Pisp,
};
use crate::context::TransactionContext;
use crate::names;
use crate::schema::{self, Fields, Object, SchemaError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    Authority,
    Checkout,
    Payment,
}

impl Family {
    pub fn open_vct(self) -> &'static str {
        match self {
            Family::Authority => names::aap::AUTHORITY_OPEN,
            Family::Checkout => names::ap2::CHECKOUT_OPEN,
            Family::Payment => names::ap2::PAYMENT_OPEN,
        }
    }

    pub fn closed_vct(self) -> &'static str {
        match self {
            Family::Authority => names::aap::ACTION,
            Family::Checkout => names::ap2::CHECKOUT,
            Family::Payment => names::ap2::PAYMENT,
        }
    }

    fn all() -> [Family; 3] {
        [Family::Authority, Family::Checkout, Family::Payment]
    }

    fn from_open(vct: &str) -> Option<Family> {
        Family::all().into_iter().find(|f| f.open_vct() == vct)
    }

    fn from_closed(vct: &str) -> Option<Family> {
        Family::all().into_iter().find(|f| f.closed_vct() == vct)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum MandateError {
    #[error("missing or non-string vct")]
    MissingType,
    #[error("unknown mandate type {0:?}")]
    UnknownType(String),
    #[error("{0:?} is a closed mandate, but an open mandate is required here")]
    NotOpen(String),
    #[error("{0:?} is an open mandate, but the chain must end in a closed mandate")]
    NotClosed(String),
    #[error("constraint {index}: {error}")]
    Constraint {
        index: usize,
        error: ConstraintError,
    },
    #[error("constraint {index}: {type_name} does not apply to {vct}")]
    NotApplicable {
        index: usize,
        type_name: &'static str,
        vct: &'static str,
    },
    #[error("{0}")]
    Schema(#[from] SchemaError),
}

/// Claims of an open mandate that are not pre-set claims.
const STRUCTURAL: &[&str] = &[
    "vct",
    "constraints",
    "cnf",
    "iat",
    "exp",
    "nbf",
    "status",
    "iss",
    "sub",
    "aud",
    "jti",
    "nonce",
    // AP2: risk signals collected by the trusted surface, not a value the
    // closed mandate has to repeat.
    "risk_data",
    names::aap::AGENT,
    names::aap::NOTE,
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenMandate {
    family: Family,
    constraints: Vec<Constraint>,
    presets: Object,
    max_depth: u32,
    ledger_key: String,
}

impl OpenMandate {
    /// `ledger_key` names this mandate's usage counter: the verifier uses
    /// the hash of the link's JWT, which stays the same however many
    /// disclosures are presented.
    pub fn parse(claims: &Object, ledger_key: impl Into<String>) -> Result<Self, MandateError> {
        let vct = vct(claims)?;
        let family = Family::from_open(vct).ok_or_else(|| match Family::from_closed(vct) {
            Some(_) => MandateError::NotOpen(vct.to_owned()),
            None => MandateError::UnknownType(vct.to_owned()),
        })?;
        let raw = match claims.get("constraints") {
            None => &[][..],
            Some(Value::Array(items)) => items.as_slice(),
            Some(_) => {
                return Err(
                    SchemaError::new(family.open_vct(), "constraints must be an array").into(),
                )
            }
        };
        let mut constraints = Vec::with_capacity(raw.len());
        for (index, item) in raw.iter().enumerate() {
            let c = Constraint::parse(item)
                .map_err(|error| MandateError::Constraint { index, error })?;
            if c.family().is_some_and(|f| f != family) {
                return Err(MandateError::NotApplicable {
                    index,
                    type_name: c.type_name(),
                    vct: family.open_vct(),
                });
            }
            constraints.push(c);
        }
        let has = |t: &str| constraints.iter().any(|c| c.type_name() == t);
        if family == Family::Authority && !has(names::aap::ACTIONS) {
            // v0's scope always had an action allow-list; an AAP mandate
            // without one would allow every action.
            return Err(SchemaError::new(
                family.open_vct(),
                format!("needs an {} constraint", names::aap::ACTIONS),
            )
            .into());
        }
        if has(names::ap2::AGENT_RECURRENCE)
            && !(has(names::ap2::AMOUNT_RANGE) && has(names::ap2::BUDGET))
        {
            return Err(SchemaError::new(
                family.open_vct(),
                "payment.agent_recurrence requires payment.amount_range and payment.budget",
            )
            .into());
        }
        // Several aap.delegation constraints all apply: the smallest wins.
        let max_depth = constraints
            .iter()
            .filter_map(|c| match c {
                Constraint::Delegation { max_depth } => Some(*max_depth),
                _ => None,
            })
            .min()
            .unwrap_or(0);
        let presets = claims
            .iter()
            .filter(|(k, _)| !STRUCTURAL.contains(&k.as_str()))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        Ok(OpenMandate {
            family,
            constraints,
            presets,
            max_depth,
            ledger_key: ledger_key.into(),
        })
    }

    pub fn family(&self) -> Family {
        self.family
    }

    pub fn constraints(&self) -> &[Constraint] {
        &self.constraints
    }

    pub fn presets(&self) -> &Object {
        &self.presets
    }

    /// How many further open mandates may follow this one (0 without
    /// `aap.delegation`).
    pub fn max_depth(&self) -> u32 {
        self.max_depth
    }

    pub fn ledger_key(&self) -> &str {
        &self.ledger_key
    }
}

/// The closed mandate: the concrete action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClosedMandate {
    content: ClosedContent,
    claims: Object,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClosedContent {
    Action(Action),
    Checkout(CheckoutMandate),
    Payment(PaymentMandate),
}

impl ClosedMandate {
    pub fn parse(claims: &Object) -> Result<Self, MandateError> {
        let vct = vct(claims)?;
        let family = Family::from_closed(vct).ok_or_else(|| match Family::from_open(vct) {
            Some(_) => MandateError::NotClosed(vct.to_owned()),
            None => MandateError::UnknownType(vct.to_owned()),
        })?;
        if claims.contains_key("constraints") {
            return Err(SchemaError::new(vct, "a closed mandate carries no constraints").into());
        }
        let value = Value::Object(claims.clone());
        let content = match family {
            Family::Authority => ClosedContent::Action(Action::parse(&value)?),
            Family::Checkout => ClosedContent::Checkout(CheckoutMandate::parse(&value)?),
            Family::Payment => ClosedContent::Payment(PaymentMandate::parse(&value)?),
        };
        Ok(ClosedMandate {
            content,
            claims: claims.clone(),
        })
    }

    pub fn content(&self) -> &ClosedContent {
        &self.content
    }

    pub fn claims(&self) -> &Object {
        &self.claims
    }

    pub fn family(&self) -> Family {
        match self.content {
            ClosedContent::Action(_) => Family::Authority,
            ClosedContent::Checkout(_) => Family::Checkout,
            ClosedContent::Payment(_) => Family::Payment,
        }
    }
}

fn vct(claims: &Object) -> Result<&str, MandateError> {
    claims
        .get("vct")
        .and_then(Value::as_str)
        .ok_or(MandateError::MissingType)
}

/// `aap.action.1 { action, resource?, amount?, counterparty?,
/// data_categories? }` (0004). Strict: an unknown member is an error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Action {
    pub action: String,
    pub resource: Option<String>,
    pub amount: Option<Amount>,
    pub counterparty: Option<String>,
    pub data_categories: Option<Vec<String>>,
}

impl Action {
    pub fn parse(value: &Value) -> Result<Self, SchemaError> {
        let mut f = Fields::new(value, names::aap::ACTION)?;
        f.allow(&[
            "vct",
            "iat",
            "exp",
            "nbf",
            "jti",
            "status",
            names::aap::NOTE,
            names::aap::AGENT,
        ]);
        let action = Action {
            action: f.string("action")?,
            resource: f.opt_string("resource")?,
            amount: f
                .opt("amount")
                .map(|v| schema::amount(v, "amount"))
                .transpose()?,
            counterparty: f.opt_string("counterparty")?,
            data_categories: f.opt_strings("data_categories")?,
        };
        f.finish()?;
        Ok(action)
    }
}

/// AP2 closed checkout mandate. `checkout_jwt` is selectively disclosable
/// and may be absent from a presentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckoutMandate {
    pub checkout_jwt: Option<String>,
    pub checkout_hash: String,
}

impl CheckoutMandate {
    pub fn parse(value: &Value) -> Result<Self, SchemaError> {
        let mut f = Fields::new(value, names::ap2::CHECKOUT)?;
        Ok(CheckoutMandate {
            checkout_jwt: f.opt_string("checkout_jwt")?,
            checkout_hash: f.string("checkout_hash")?,
        })
    }

    /// Binds the closed mandate to the checkout and returns the checkout
    /// object if it can be trusted:
    ///
    /// 1. A `checkout_jwt` is known: disclosed in the mandate, or the
    ///    verifier's own (they must agree).
    /// 2. `checkout_hash` is its hash under the mandate's `_sd_alg` (AP2:
    ///    the merchant MUST check this), and equals the verifier's expected
    ///    hash if it has one.
    /// 3. Its content is trusted only if it is the verifier's own JWT or
    ///    carries a valid signature by `tx.merchant_key`. The AP2 SDK
    ///    decodes it without checking the signature.
    ///
    /// `Ok(None)`: bound, but the content is not trusted, so constraints
    /// that read it are unresolved.
    pub fn bind(
        &self,
        sd_alg: SdAlg,
        tx: &TransactionContext,
    ) -> Result<Option<Checkout>, Failure> {
        let jwt = match (&self.checkout_jwt, &tx.checkout_jwt) {
            (Some(disclosed), Some(own)) if disclosed != own => {
                return Err(violated("the disclosed checkout_jwt is not the verifier's"))
            }
            (Some(jwt), _) | (None, Some(jwt)) => jwt,
            (None, None) => {
                return Err(unresolved(
                    "checkout_jwt is neither disclosed nor known to the verifier, so checkout_hash cannot be checked",
                ))
            }
        };
        if sd_alg.digest(jwt) != self.checkout_hash {
            return Err(violated("checkout_hash does not match checkout_jwt"));
        }
        if tx
            .expected_checkout_hash
            .as_ref()
            .is_some_and(|h| *h != self.checkout_hash)
        {
            return Err(violated(
                "checkout_hash is not the checkout the verifier expects",
            ));
        }
        let payload = if tx.checkout_jwt.is_some() {
            decode_payload(jwt).ok_or_else(|| violated("checkout_jwt is not a JWT"))?
        } else if let Some(key) = &tx.merchant_key {
            Value::Object(
                verify_jwt(jwt, key, &["JWT"])
                    .map_err(|e| violated(format!("checkout_jwt: {e}")))?
                    .claims()
                    .clone(),
            )
        } else {
            return Ok(None);
        };
        Checkout::parse(&payload)
            .map(Some)
            .map_err(|e| violated(e.to_string()))
    }
}

fn decode_payload(jwt: &str) -> Option<Value> {
    let mut parts = jwt.split('.');
    let (_, payload, _, None) = (parts.next()?, parts.next()?, parts.next()?, parts.next()) else {
        return None;
    };
    serde_json::from_slice(&B64.decode(payload).ok()?).ok()
}

/// The parts of a UCP checkout object the AP2 checkout constraints read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkout {
    pub merchant: Option<Merchant>,
    /// Item id and total quantity, one entry per distinct item.
    pub line_items: Vec<(String, u64)>,
}

impl Checkout {
    pub fn parse(value: &Value) -> Result<Self, SchemaError> {
        let mut f = Fields::new(value, "checkout")?;
        let merchant = f.opt("merchant").map(Merchant::parse).transpose()?;
        let items = f
            .req("line_items")?
            .as_array()
            .ok_or_else(|| f.error("line_items must be an array"))?;
        let mut line_items: Vec<(String, u64)> = Vec::new();
        for item in items {
            let mut li = Fields::new(item, "line item")?;
            let id = Fields::new(li.req("item")?, "item")?.string("id")?;
            let quantity = li.uint("quantity")?;
            if quantity == 0 {
                return Err(li.error("quantity must be at least 1"));
            }
            match line_items.iter_mut().find(|(sku, _)| *sku == id) {
                Some((_, q)) => {
                    *q = q
                        .checked_add(quantity)
                        .ok_or_else(|| li.error("quantity overflow"))?
                }
                None => line_items.push((id, quantity)),
            }
        }
        Ok(Checkout {
            merchant,
            line_items,
        })
    }
}

/// AP2 closed payment mandate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentMandate {
    pub transaction_id: String,
    pub payee: Merchant,
    pub pisp: Option<Pisp>,
    pub payment_amount: Amount,
    pub payment_instrument: PaymentInstrument,
    pub execution_date: Option<String>,
}

impl PaymentMandate {
    pub fn parse(value: &Value) -> Result<Self, SchemaError> {
        let mut f = Fields::new(value, names::ap2::PAYMENT)?;
        Ok(PaymentMandate {
            transaction_id: f.string("transaction_id")?,
            payee: Merchant::parse(f.req("payee")?)?,
            pisp: f.opt("pisp").map(Pisp::parse).transpose()?,
            payment_amount: schema::amount(f.req("payment_amount")?, "payment_amount")?,
            payment_instrument: PaymentInstrument::parse(f.req("payment_instrument")?)?,
            execution_date: f.opt_string("execution_date")?,
        })
    }

    /// The payment must be for the checkout the verifier is settling:
    /// `transaction_id` is that checkout's hash. Without the verifier's own
    /// value there is nothing to compare, so this fails closed.
    pub fn bind(&self, tx: &TransactionContext) -> Result<(), Failure> {
        match &tx.expected_transaction_id {
            None => Err(unresolved(
                "the verifier must supply the transaction_id (checkout hash) it settles",
            )),
            Some(id) if *id == self.transaction_id => Ok(()),
            Some(_) => Err(violated("transaction_id is not the checkout being paid")),
        }
    }
}
