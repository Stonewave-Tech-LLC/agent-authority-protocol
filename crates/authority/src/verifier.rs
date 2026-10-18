//! The v1 verifier (0004 "Verification semantics", V1–V6).
//!
//! ```text
//! V1  aap-sdjwt: signatures, sd_hash chain, disclosures, typ per position
//! V2  aap-sdjwt: nbf/exp of every element on the verifier's clock
//!     here:      status of every element that has one; short expiry for
//!                elements without (0005 CG15)
//! V3  here:      depth against every ancestor's aap.delegation
//! V4  here:      every open mandate's constraints and pre-set claims,
//!                cumulatively, plus AP2's transaction bindings
//!                (checkout_hash, transaction_id)
//! V5  aap-sdjwt: aud / nonce / iat window of the final binding,
//!     here:      re-checked on the verified chain; agent nonces replay-checked
//! V6  here:      a signed Mandate Receipt for every outcome
//! ```
//!
//! Authorization code only ever sees a [`VerifiedChain`]: [`Authorized`]
//! has no public constructor and is built from one, so unverified data
//! cannot be mistaken for an authorized action.

use std::iter;

use aap_sdjwt::{
    KeyBinding, Position, Presentation, RootForm, SdAlg, SdJwt, Signer, Unverified, VerifiedChain,
    VerifiedLink, VerifyOptions, VerifyingKey,
};
use serde_json::Value;
use thiserror::Error;

use crate::constraint::Failure;
use crate::context::{EvalEnv, Nonce, TransactionContext, UsageLedger};
use crate::evaluate::{evaluate_chain, Cause};
use crate::mandate::{ClosedContent, ClosedMandate, MandateError, OpenMandate};
use crate::nonce::NonceStore;
use crate::receipt::{ErrorCode, MandateReceipt};
use crate::status::{StatusChecker, TokenStatus};
use crate::ConstraintError;

/// What the chain is rooted in. Decided by the verifier, never by the
/// presentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootPolicy {
    /// 0004's target shape: the root is the user credential (SD-JWT VC,
    /// AL2/AL3) signed by the Issuer Service; the principal is that
    /// credential, and every mandate is a link after it. `vct` lists the
    /// accepted credential types.
    Credential { typ: Vec<String>, vct: Vec<String> },
    /// AP2's shape: the root *is* the first mandate, signed by the user's
    /// key, in Delegate Payload form. The "issuer key" passed to
    /// [`Verifier::verify`] is the user's key, known to the verifier out of
    /// band.
    UserSignedMandate { typ: Vec<String> },
}

#[derive(Debug, Clone)]
pub struct Policy {
    /// This verifier, as it appears in `aud`.
    pub audience: String,
    pub root: RootPolicy,
    /// Clock skew tolerated on `exp` and `nbf`, seconds.
    pub leeway: i64,
    /// How old the final binding's `iat` may be (0004 V5: 5 minutes).
    pub max_age: i64,
    /// How far ahead the final binding's `iat` may be (0004 V5: 30 s).
    pub max_future: i64,
    /// Upper bound on open mandates in one chain, on top of every
    /// mandate's own `aap.delegation`.
    pub max_open_mandates: usize,
    /// An open mandate without `status` cannot be revoked, so it must
    /// expire within this many seconds of `now` (0005 CG15 proposes 1 h).
    pub max_validity_without_status: i64,
    /// Accept AP2 human-present mandates: a user-signed closed mandate as
    /// the whole presentation, with **no** `aud`, `nonce` or fresh `iat`,
    /// hence replayable to any verifier until it expires. Off by default;
    /// AAP's own form (0005 CG2) puts the closed mandate in a link signed
    /// by the user key, which is bound like any other.
    pub allow_unbound_root_mandate: bool,
}

impl Policy {
    pub fn new(audience: impl Into<String>, root: RootPolicy) -> Self {
        Policy {
            audience: audience.into(),
            root,
            leeway: 0,
            max_age: 300,
            max_future: 30,
            max_open_mandates: 4,
            max_validity_without_status: 3600,
            allow_unbound_root_mandate: false,
        }
    }
}

/// On whose behalf the action happens: derived from the root only, never
/// restated in a link (0004).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Principal {
    /// The holder of the user credential: its issuer and confirmed key.
    Credential {
        issuer: Option<String>,
        user_key: Option<VerifyingKey>,
    },
    /// The owner of the key that signed the root mandate.
    UserKey(VerifyingKey),
}

/// Why a presentation was rejected. [`Reason::code`] maps it to the
/// receipt's error code.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Reason {
    #[error("presentation does not verify: {0}")]
    Credential(aap_sdjwt::Error),
    #[error("the closed mandate is not bound to this transaction (no aud/nonce/iat)")]
    Unbound,
    #[error("the presentation contains no mandate")]
    NoMandate,
    #[error("root credential type not accepted")]
    RootNotAccepted,
    #[error("{position}: status is {status:?}")]
    Revoked {
        position: Position,
        status: TokenStatus,
    },
    #[error("{position}: {message}")]
    StatusUnavailable { position: Position, message: String },
    #[error("{position}: no status entry and valid for too long to go unrevocable")]
    Unrevocable { position: Position },
    #[error("more open mandates than this verifier accepts")]
    TooManyMandates,
    #[error("{position}: {further} further open mandate(s), but max_depth is {max_depth}")]
    DelegationDepth {
        position: Position,
        max_depth: u32,
        further: usize,
    },
    #[error("{position}: {error}")]
    Mandate {
        position: Position,
        error: MandateError,
    },
    #[error("{position}: {failure}")]
    Binding {
        position: Position,
        failure: Failure,
    },
    #[error("{position}: {cause}")]
    Chain { position: Position, cause: Cause },
    #[error("key binding: {0}")]
    Freshness(&'static str),
    #[error("nonce already used")]
    Replay,
    #[error("{0}")]
    NonceStore(String),
}

impl Reason {
    pub fn code(&self) -> ErrorCode {
        use ErrorCode::*;
        match self {
            Reason::Mandate { error, .. } => match error {
                MandateError::Constraint {
                    error: ConstraintError::Unknown(_),
                    ..
                }
                | MandateError::NotApplicable { .. } => UnresolvedConstraint,
                _ => InvalidMandate,
            },
            Reason::Binding {
                failure: Failure::Unresolved(_),
                ..
            }
            | Reason::Chain {
                cause:
                    Cause::Constraint {
                        failure: Failure::Unresolved(_),
                        ..
                    },
                ..
            } => UnresolvedConstraint,
            Reason::TooManyMandates
            | Reason::DelegationDepth { .. }
            | Reason::Binding { .. }
            | Reason::Chain { .. } => InvalidMandate,
            Reason::Credential(_)
            | Reason::Unbound
            | Reason::NoMandate
            | Reason::RootNotAccepted
            | Reason::Revoked { .. }
            | Reason::StatusUnavailable { .. }
            | Reason::Unrevocable { .. }
            | Reason::Freshness(_)
            | Reason::Replay
            | Reason::NonceStore(_) => InvalidCredential,
        }
    }
}

/// An action this verifier has authorized. Only [`Verifier::verify`]
/// creates one, and only from a [`VerifiedChain`].
#[derive(Debug, Clone)]
pub struct Authorized {
    chain: VerifiedChain,
    closed: ClosedMandate,
    principal: Principal,
    ledger_keys: Vec<String>,
}

impl Authorized {
    pub fn chain(&self) -> &VerifiedChain {
        &self.chain
    }

    /// The concrete action, already checked against every open mandate.
    pub fn closed(&self) -> &ClosedMandate {
        &self.closed
    }

    pub fn principal(&self) -> &Principal {
        &self.principal
    }

    /// The usage counter of every open mandate, root first. Record the
    /// accepted use under each (0005 CG4: shared budgets are counted
    /// against the user-signed mandate, which sub-delegations share).
    pub fn ledger_keys(&self) -> &[String] {
        &self.ledger_keys
    }
}

/// The outcome and its signed receipt. There is no outcome without a
/// receipt: if signing fails, [`Verifier::verify`] fails.
#[derive(Debug)]
pub struct Decision {
    outcome: Result<Authorized, Reason>,
    receipt: MandateReceipt,
    receipt_jwt: String,
}

impl Decision {
    pub fn outcome(&self) -> Result<&Authorized, &Reason> {
        self.outcome.as_ref()
    }

    pub fn into_outcome(self) -> Result<Authorized, Reason> {
        self.outcome
    }

    pub fn receipt(&self) -> &MandateReceipt {
        &self.receipt
    }

    /// The receipt as a JWS, to return to the agent.
    pub fn receipt_jwt(&self) -> &str {
        &self.receipt_jwt
    }
}

pub struct Verifier<'a> {
    policy: Policy,
    issuer: String,
    receipt_signer: &'a dyn Signer,
    status: &'a dyn StatusChecker,
    nonces: Option<&'a dyn NonceStore>,
    ledger: Option<&'a dyn UsageLedger>,
}

impl<'a> Verifier<'a> {
    /// `issuer` is the receipts' `iss`.
    pub fn new(
        policy: Policy,
        issuer: impl Into<String>,
        receipt_signer: &'a dyn Signer,
        status: &'a dyn StatusChecker,
    ) -> Self {
        Verifier {
            policy,
            issuer: issuer.into(),
            receipt_signer,
            status,
            nonces: None,
            ledger: None,
        }
    }

    /// Required for [`Nonce::AgentGenerated`].
    pub fn with_nonce_store(mut self, store: &'a dyn NonceStore) -> Self {
        self.nonces = Some(store);
        self
    }

    /// Required for `payment.budget` and `payment.agent_recurrence`.
    pub fn with_ledger(mut self, ledger: &'a dyn UsageLedger) -> Self {
        self.ledger = Some(ledger);
        self
    }

    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// Verifies and authorizes `presentation` at the verifier's time `now`.
    /// `issuer_key` is the root's signer: the Issuer Service for a
    /// credential root, the user for a user-signed root mandate.
    pub fn verify(
        &self,
        presentation: &str,
        issuer_key: &VerifyingKey,
        tx: &TransactionContext,
        now: i64,
    ) -> Result<Decision, aap_sdjwt::Error> {
        let (outcome, reference, aap_chain) = match Unverified::<Presentation>::parse(presentation)
        {
            Err(e) => (
                Err(Reason::Credential(e)),
                SdAlg::Sha256.digest(presentation),
                Vec::new(),
            ),
            Ok(parsed) => {
                // Hashes of what was received, verified or not, so a
                // rejection receipt still says what it rejects.
                let p = parsed.inner();
                let hash = |e: &SdJwt| e.sd_alg().unwrap_or_default().digest(&e.serialize());
                let chain = iter::once(p.root()).chain(p.links()).map(hash).collect();
                let reference = hash(p.last());
                (self.check(&parsed, issuer_key, tx, now), reference, chain)
            }
        };
        let receipt = MandateReceipt {
            iss: self.issuer.clone(),
            iat: now,
            reference,
            error: outcome.as_ref().err().map(|r| (r.code(), r.to_string())),
            aap_chain,
        };
        let receipt_jwt = receipt.sign(self.receipt_signer)?;
        Ok(Decision {
            outcome,
            receipt,
            receipt_jwt,
        })
    }

    fn check(
        &self,
        parsed: &Unverified<Presentation>,
        issuer_key: &VerifyingKey,
        tx: &TransactionContext,
        now: i64,
    ) -> Result<Authorized, Reason> {
        let p = parsed.inner();
        let (root_typ, root_form) = match &self.policy.root {
            RootPolicy::Credential { typ, .. } => (typ, RootForm::Credential),
            RootPolicy::UserSignedMandate { typ } => (typ, RootForm::DelegatePayload),
        };
        let (key_binding, nonce) = if !p.links().is_empty() {
            let nonce = match &tx.nonce {
                Nonce::Challenge(n) => n.clone(),
                // Read before verification only to know what to compare
                // against; it is checked like a challenge, then for replay.
                Nonce::AgentGenerated => p
                    .last()
                    .unverified_payload()
                    .get("nonce")
                    .and_then(Value::as_str)
                    .ok_or(Reason::Freshness("the closed mandate has no nonce"))?
                    .to_owned(),
            };
            let binding = KeyBinding::TerminalLink {
                audience: self.policy.audience.clone(),
                nonce: nonce.clone(),
            };
            (binding, Some(nonce))
        } else if self.policy.allow_unbound_root_mandate && root_form == RootForm::DelegatePayload {
            (KeyBinding::NotRequired, None)
        } else {
            return Err(Reason::Unbound);
        };
        let options = VerifyOptions {
            now,
            root_typ: root_typ.clone(),
            root_form,
            key_binding,
            leeway: self.policy.leeway,
            max_age: self.policy.max_age,
            max_future: self.policy.max_future,
            require_exp: true,
            max_links: self.policy.max_open_mandates + 1,
        };
        let chain = parsed
            .verify(issuer_key, &options)
            .map_err(Reason::Credential)?;
        self.authorize(chain, issuer_key, tx, nonce, now)
    }

    /// V2–V5 on a verified chain.
    fn authorize(
        &self,
        chain: VerifiedChain,
        issuer_key: &VerifyingKey,
        tx: &TransactionContext,
        nonce: Option<String>,
        now: i64,
    ) -> Result<Authorized, Reason> {
        let (principal, first_mandate) = match &self.policy.root {
            RootPolicy::Credential { vct, .. } => {
                let root = chain.root();
                let claim = |name| root.claims().get(name).and_then(Value::as_str);
                if !claim("vct").is_some_and(|v| vct.iter().any(|x| x == v)) {
                    return Err(Reason::RootNotAccepted);
                }
                let principal = Principal::Credential {
                    issuer: claim("iss").map(str::to_owned),
                    user_key: root.cnf().cloned(),
                };
                (principal, 1)
            }
            RootPolicy::UserSignedMandate { .. } => (Principal::UserKey(issuer_key.clone()), 0),
        };
        let (leaf, opens) = chain.links()[first_mandate..]
            .split_last()
            .ok_or(Reason::NoMandate)?;
        if opens.len() > self.policy.max_open_mandates {
            return Err(Reason::TooManyMandates);
        }

        // V2: status of every element that has one.
        for element in chain.links() {
            self.check_status(element, now)?;
        }

        let closed = ClosedMandate::parse(leaf.claims()).map_err(|error| Reason::Mandate {
            position: leaf.position(),
            error,
        })?;
        let mut mandates = Vec::with_capacity(opens.len());
        for link in opens {
            let open = OpenMandate::parse(link.claims(), ledger_key(link)).map_err(|error| {
                Reason::Mandate {
                    position: link.position(),
                    error,
                }
            })?;
            if !link.claims().contains_key("status") {
                let exp = link.claims().get("exp").and_then(Value::as_f64);
                if !exp.is_some_and(|exp| {
                    exp - now as f64 <= self.policy.max_validity_without_status as f64
                }) {
                    return Err(Reason::Unrevocable {
                        position: link.position(),
                    });
                }
            }
            mandates.push(open);
        }

        // V3: no open mandate is followed by more open mandates than its
        // own aap.delegation allows (none without one).
        for (i, (open, link)) in mandates.iter().zip(opens).enumerate() {
            let further = mandates.len() - 1 - i;
            if further > open.max_depth() as usize {
                return Err(Reason::DelegationDepth {
                    position: link.position(),
                    max_depth: open.max_depth(),
                    further,
                });
            }
        }

        // V4: AP2's transaction bindings, then every open mandate.
        let binding_error = |failure| Reason::Binding {
            position: leaf.position(),
            failure,
        };
        let checkout = match closed.content() {
            ClosedContent::Checkout(c) => c.bind(leaf.sd_alg(), tx).map_err(binding_error)?,
            ClosedContent::Payment(p) => {
                p.bind(tx).map_err(binding_error)?;
                None
            }
            ClosedContent::Action(_) => None,
        };
        let env = EvalEnv {
            now,
            tx,
            ledger: self.ledger,
            checkout: checkout.as_ref(),
        };
        evaluate_chain(&mandates, &closed, &env).map_err(|f| Reason::Chain {
            position: opens[f.link].position(),
            cause: f.cause,
        })?;

        // V5, on the verified chain (aap-sdjwt already enforced it), then
        // replay for nonces the agent chose.
        if let Some(nonce) = &nonce {
            let iat = self.check_freshness(leaf, nonce, now)?;
            if tx.nonce == Nonce::AgentGenerated {
                let store = self
                    .nonces
                    .ok_or_else(|| Reason::NonceStore("no nonce store configured".into()))?;
                match store.check_and_insert(nonce, iat + self.policy.max_age, now) {
                    Ok(true) => {}
                    Ok(false) => return Err(Reason::Replay),
                    Err(e) => return Err(Reason::NonceStore(e.to_string())),
                }
            }
        }

        let ledger_keys = mandates.iter().map(|m| m.ledger_key().to_owned()).collect();
        Ok(Authorized {
            chain,
            closed,
            principal,
            ledger_keys,
        })
    }

    fn check_status(&self, element: &VerifiedLink, now: i64) -> Result<(), Reason> {
        let Some(status) = element.claims().get("status") else {
            return Ok(());
        };
        match self.status.check(status, now) {
            Ok(TokenStatus::Valid) => Ok(()),
            Ok(status) => Err(Reason::Revoked {
                position: element.position(),
                status,
            }),
            Err(e) => Err(Reason::StatusUnavailable {
                position: element.position(),
                message: e.to_string(),
            }),
        }
    }

    fn check_freshness(&self, leaf: &VerifiedLink, nonce: &str, now: i64) -> Result<i64, Reason> {
        let env = leaf.envelope();
        if env.get("aud").and_then(Value::as_str) != Some(self.policy.audience.as_str()) {
            return Err(Reason::Freshness("aud is not this verifier"));
        }
        if env.get("nonce").and_then(Value::as_str) != Some(nonce) {
            return Err(Reason::Freshness("nonce mismatch"));
        }
        let iat = env
            .get("iat")
            .and_then(Value::as_f64)
            .ok_or(Reason::Freshness("no iat"))?;
        let now_f = now as f64;
        if iat < now_f - self.policy.max_age as f64 || iat > now_f + self.policy.max_future as f64 {
            return Err(Reason::Freshness("iat outside the freshness window"));
        }
        Ok(iat as i64)
    }
}

/// The usage counter of an open mandate: hash of its JWT, which does not
/// change with the disclosures a presentation selects.
fn ledger_key(link: &VerifiedLink) -> String {
    let jwt = link.sd_jwt().split('~').next().unwrap_or_default();
    SdAlg::Sha256.digest(jwt)
}
