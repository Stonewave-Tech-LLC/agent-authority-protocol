//! The 9-step verification flow from docs/verification-flow.md. This is the
//! only place authority is granted — everything above (issuance, tokens,
//! scope) exists to make this function's job either trivially satisfiable
//! or a hard, explicit rejection.

use chrono::Utc;

use crate::jws::jwk_to_public_key;
use crate::nonce::NonceStore;
use crate::resolver::KeyResolver;
use crate::scope;
use crate::status::StatusChecker;
use crate::token::{AgentMessageToken, DelegationToken};
use crate::types::{AgentMessage, Delegation, VerificationFailure};

pub struct VerifiedAction {
    /// Leaf first, root (principal-issued) last.
    pub delegation_chain: Vec<Delegation>,
    pub agent_message: AgentMessage,
}

pub struct Verifier<'a, R: KeyResolver, S: StatusChecker, N: NonceStore> {
    audience: String,
    resolver: &'a R,
    status: &'a S,
    nonces: &'a N,
}

impl<'a, R: KeyResolver, S: StatusChecker, N: NonceStore> Verifier<'a, R, S, N> {
    pub fn new(audience: impl Into<String>, resolver: &'a R, status: &'a S, nonces: &'a N) -> Self {
        Self {
            audience: audience.into(),
            resolver,
            status,
            nonces,
        }
    }

    /// `delegation_chain_jws` is ordered leaf-first: index 0 is the
    /// delegation bound to the agent actually making the request; each
    /// subsequent entry is its parent, up to the principal-issued root.
    /// A direct (non-chained) delegation is simply a chain of length 1.
    pub fn verify(
        &self,
        delegation_chain_jws: &[&str],
        agent_message_jws: &str,
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

            let now = Utc::now();
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
        if self
            .nonces
            .seen_and_record(&verified_msg.payload.agent_id, &verified_msg.payload.nonce)
        {
            return Err(VerificationFailure::NonceReplayed);
        }

        if !scope::matches(&leaf.scope, &verified_msg.payload.request) {
            return Err(VerificationFailure::ScopeDenied);
        }

        Ok(VerifiedAction {
            delegation_chain: verified_payloads,
            agent_message: verified_msg.payload,
        })
    }
}
