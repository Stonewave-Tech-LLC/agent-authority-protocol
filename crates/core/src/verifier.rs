//! The 9-step verification flow from docs/verification-flow.md, plus a
//! signed Receipt for every outcome. This is the only place authority is
//! granted — everything above (issuance, tokens, scope) exists to make this
//! function's job either trivially satisfiable or a hard, explicit
//! rejection, and every call leaves behind a durable, checkable record of
//! which one it was.

use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;

use crate::jws::jwk_to_public_key;
use crate::nonce::NonceStore;
use crate::receipt::{digest_request, Receipt, ReceiptOutcome};
use crate::resolver::KeyResolver;
use crate::scope;
use crate::signer::Signer;
use crate::status::StatusChecker;
use crate::token::{AgentMessageToken, DelegationToken};
use crate::types::{AgentMessage, Delegation, VerificationFailure};

pub struct VerifiedAction {
    /// Leaf first, root (principal-issued) last.
    pub delegation_chain: Vec<Delegation>,
    pub agent_message: AgentMessage,
}

pub struct IssuedReceipt {
    pub jws: String,
    pub payload: Receipt,
}

pub struct VerificationOutcome {
    pub decision: Result<VerifiedAction, VerificationFailure>,
    /// Signed regardless of `decision` — a rejection is recorded just as
    /// durably as an acceptance.
    pub receipt: IssuedReceipt,
}

pub struct Verifier<'a, R: KeyResolver, S: StatusChecker, N: NonceStore, SG: Signer> {
    verifier_id: String,
    audience: String,
    resolver: &'a R,
    status: &'a S,
    nonces: &'a N,
    receipt_signer: &'a SG,
    max_message_age: Duration,
    max_clock_skew: Duration,
}

/// How old an AgentMessage may be when it reaches the Verifier. Without a
/// bound, a signed message stays valid forever and only the nonce store
/// stands between it and a replay — which then has to remember every nonce
/// ever seen.
pub const DEFAULT_MAX_MESSAGE_AGE_SECS: i64 = 300;
/// How far an agent's clock may run ahead of the Verifier's.
pub const DEFAULT_MAX_CLOCK_SKEW_SECS: i64 = 60;

impl<'a, R: KeyResolver, S: StatusChecker, N: NonceStore, SG: Signer> Verifier<'a, R, S, N, SG> {
    pub fn new(
        verifier_id: impl Into<String>,
        audience: impl Into<String>,
        resolver: &'a R,
        status: &'a S,
        nonces: &'a N,
        receipt_signer: &'a SG,
    ) -> Self {
        Self {
            verifier_id: verifier_id.into(),
            audience: audience.into(),
            resolver,
            status,
            nonces,
            receipt_signer,
            max_message_age: Duration::seconds(DEFAULT_MAX_MESSAGE_AGE_SECS),
            max_clock_skew: Duration::seconds(DEFAULT_MAX_CLOCK_SKEW_SECS),
        }
    }

    /// Overrides the default freshness window for `AgentMessage.issued_at`.
    /// A nonce store only needs to remember nonces for `max_age + max_skew`:
    /// anything older is rejected as stale before the nonce is consulted.
    pub fn with_message_freshness(mut self, max_age: Duration, max_skew: Duration) -> Self {
        self.max_message_age = max_age;
        self.max_clock_skew = max_skew;
        self
    }

    /// `delegation_chain_jws` is ordered leaf-first: index 0 is the
    /// delegation bound to the agent actually making the request; each
    /// subsequent entry is its parent, up to the principal-issued root.
    /// A direct (non-chained) delegation is simply a chain of length 1.
    pub fn verify(
        &self,
        delegation_chain_jws: &[&str],
        agent_message_jws: &str,
    ) -> VerificationOutcome {
        self.verify_at(delegation_chain_jws, agent_message_jws, Utc::now())
    }

    /// Same as `verify`, evaluated at an explicit point in time. Every time
    /// check in the flow (delegation validity, message freshness, scope time
    /// windows, the receipt's `decided_at`) uses this one `now`, so a
    /// decision is reproducible and testable.
    pub fn verify_at(
        &self,
        delegation_chain_jws: &[&str],
        agent_message_jws: &str,
        now: DateTime<Utc>,
    ) -> VerificationOutcome {
        let decision = self.verify_inner(delegation_chain_jws, agent_message_jws, now);
        let receipt = self.issue_receipt(delegation_chain_jws, agent_message_jws, &decision, now);
        VerificationOutcome { decision, receipt }
    }

    fn verify_inner(
        &self,
        delegation_chain_jws: &[&str],
        agent_message_jws: &str,
        now: DateTime<Utc>,
    ) -> Result<VerifiedAction, VerificationFailure> {
        if delegation_chain_jws.is_empty() {
            return Err(VerificationFailure::ChainBroken("empty chain".into()));
        }

        let mut verified_payloads: Vec<Delegation> = Vec::with_capacity(delegation_chain_jws.len());

        for (i, jws) in delegation_chain_jws.iter().enumerate() {
            let unverified = DelegationToken::from_jws(*jws)
                .map_err(|_| VerificationFailure::InvalidDelegationSignature)?;

            let signer_key = if i + 1 < delegation_chain_jws.len() {
                // Intermediate link: signed by the agent holding the parent
                // link's delegated authority, i.e. the parent's own agent key.
                let parent_unverified = DelegationToken::from_jws(delegation_chain_jws[i + 1])
                    .map_err(|_| {
                        VerificationFailure::ChainBroken("cannot parse parent link".into())
                    })?;
                jwk_to_public_key(&parent_unverified.payload.agent_public_key)
                    .map_err(|_| VerificationFailure::InvalidDelegationSignature)?
            } else {
                // Root: signed by the Principal.
                self.resolver
                    .resolve_principal_key(&unverified.payload.principal_id)
                    .map_err(VerificationFailure::KeyResolutionFailed)?
            };

            let verified = unverified
                .verify_signature(&signer_key)
                .map_err(|_| VerificationFailure::InvalidDelegationSignature)?;

            if now < verified.payload.valid_from {
                return Err(VerificationFailure::NotYetValid);
            }
            if now > verified.payload.valid_until {
                return Err(VerificationFailure::Expired);
            }
            if self.status.is_revoked(&verified.payload.delegation_id) {
                return Err(VerificationFailure::Revoked);
            }

            verified_payloads.push(verified.payload);
        }

        // Chain integrity: parent linkage, can_delegate, depth, scope narrowing.
        for i in 0..verified_payloads.len().saturating_sub(1) {
            let (child, parent) = (&verified_payloads[i], &verified_payloads[i + 1]);
            if child.parent_delegation_id != Some(parent.delegation_id) {
                return Err(VerificationFailure::ChainBroken(
                    "parent_delegation_id does not match the next link".into(),
                ));
            }
            // The principal is fixed by the root. A link restating a different
            // principal would let a sub-delegating agent claim to act for
            // someone else — exactly the misattribution this protocol exists
            // to prevent.
            if child.principal_id != parent.principal_id
                || child.principal_type != parent.principal_type
            {
                return Err(VerificationFailure::ChainBroken(
                    "sub-delegation names a different principal than its parent".into(),
                ));
            }
            if child.valid_from < parent.valid_from || child.valid_until > parent.valid_until {
                return Err(VerificationFailure::ChainBroken(
                    "sub-delegation is valid outside its parent's validity period".into(),
                ));
            }
            if !parent.can_delegate {
                return Err(VerificationFailure::ChainBroken(
                    "parent delegation does not permit sub-delegation".into(),
                ));
            }
            if let Some(max_depth) = parent.max_delegation_depth {
                if (i + 1) as u32 > max_depth {
                    return Err(VerificationFailure::ChainTooDeep);
                }
            }
            if !scope::narrows(&parent.scope, &child.scope) {
                return Err(VerificationFailure::ScopeNotNarrowed);
            }
        }

        let leaf = &verified_payloads[0];

        let agent_key = jwk_to_public_key(&leaf.agent_public_key)
            .map_err(|_| VerificationFailure::InvalidAgentSignature)?;
        let verified_msg = AgentMessageToken::from_jws(agent_message_jws)
            .map_err(|_| VerificationFailure::InvalidAgentSignature)?
            .verify_signature(&agent_key)
            .map_err(|_| VerificationFailure::InvalidAgentSignature)?;

        if verified_msg.payload.audience != self.audience {
            return Err(VerificationFailure::AudienceMismatch);
        }
        if verified_msg.payload.agent_id != leaf.agent_id {
            return Err(VerificationFailure::ChainBroken(
                "agent_id in message does not match the leaf delegation".into(),
            ));
        }
        if verified_msg.payload.issued_at > now + self.max_clock_skew {
            return Err(VerificationFailure::MessageFromFuture);
        }
        if verified_msg.payload.issued_at < now - self.max_message_age {
            return Err(VerificationFailure::StaleMessage);
        }
        if self
            .nonces
            .seen_and_record(&verified_msg.payload.agent_id, &verified_msg.payload.nonce)
        {
            return Err(VerificationFailure::NonceReplayed);
        }

        if !scope::matches(&leaf.scope, &verified_msg.payload.request, now) {
            return Err(VerificationFailure::ScopeDenied);
        }

        Ok(VerifiedAction {
            delegation_chain: verified_payloads,
            agent_message: verified_msg.payload,
        })
    }

    fn issue_receipt(
        &self,
        delegation_chain_jws: &[&str],
        agent_message_jws: &str,
        decision: &Result<VerifiedAction, VerificationFailure>,
        now: DateTime<Utc>,
    ) -> IssuedReceipt {
        let (delegation_ids, agent_id, outcome): (Vec<Uuid>, String, ReceiptOutcome) =
            match decision {
                Ok(action) => (
                    action
                        .delegation_chain
                        .iter()
                        .map(|d| d.delegation_id)
                        .collect(),
                    action.agent_message.agent_id.clone(),
                    ReceiptOutcome::Accepted,
                ),
                Err(reason) => {
                    // Best-effort, unverified: enough for the receipt to be
                    // traceable even when the cryptographic check itself is
                    // what failed. Never treated as authorization — only ever
                    // read back off an already-rejected receipt.
                    let leaf = delegation_chain_jws
                        .first()
                        .and_then(|jws| DelegationToken::from_jws(*jws).ok());

                    let agent_id = AgentMessageToken::from_jws(agent_message_jws)
                        .ok()
                        .map(|t| t.payload.agent_id)
                        .or_else(|| leaf.as_ref().map(|t| t.payload.agent_id.clone()))
                        .unwrap_or_else(|| "unknown".to_string());

                    let delegation_ids = leaf
                        .map(|t| vec![t.payload.delegation_id])
                        .unwrap_or_default();

                    (
                        delegation_ids,
                        agent_id,
                        ReceiptOutcome::Rejected {
                            reason: reason.to_string(),
                        },
                    )
                }
            };

        let payload = Receipt {
            receipt_id: Uuid::new_v4(),
            verifier_id: self.verifier_id.clone(),
            agent_id,
            delegation_ids,
            request_digest: digest_request(agent_message_jws),
            outcome,
            decided_at: now,
        };

        let jws = self
            .receipt_signer
            .sign_payload(&payload)
            .expect("signing a receipt with a local key must not fail");

        IssuedReceipt { jws, payload }
    }
}
