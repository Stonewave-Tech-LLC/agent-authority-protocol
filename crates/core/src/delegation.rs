//! Principal-side issuance: build and sign a `Delegation`.

use chrono::{Duration, Utc};
use serde_json::Value;
use uuid::Uuid;

use crate::jws::JwsError;
use crate::signer::Signer;
use crate::types::{Delegation, PrincipalType, PublicKeyJwk, Scope};

pub struct IssuedDelegation {
    pub jws: String,
    pub payload: Delegation,
}

pub struct DelegationParams {
    pub principal_id: String,
    pub principal_type: PrincipalType,
    pub agent_id: String,
    pub agent_public_key: PublicKeyJwk,
    pub scope: Scope,
    pub valid_for: Duration,
    pub status_endpoint: String,
    pub can_delegate: bool,
    pub max_delegation_depth: Option<u32>,
    pub parent_delegation_id: Option<Uuid>,
    pub metadata: Option<Value>,
}

/// `principal_signer` must be the Principal's own key (never the Agent's).
/// For a sub-delegation, pass the delegating *Agent's* signer instead and
/// set `parent_delegation_id` — the Verifier checks that link via the
/// parent's `agent_public_key`, not via `resolve_principal_key`.
pub fn issue(
    principal_signer: &impl Signer,
    params: DelegationParams,
) -> Result<IssuedDelegation, JwsError> {
    let now = Utc::now();
    let payload = Delegation {
        delegation_id: Uuid::new_v4(),
        principal_id: params.principal_id,
        principal_type: params.principal_type,
        agent_id: params.agent_id,
        agent_public_key: params.agent_public_key,
        scope: params.scope,
        valid_from: now,
        valid_until: now + params.valid_for,
        status_endpoint: params.status_endpoint,
        can_delegate: params.can_delegate,
        max_delegation_depth: params.max_delegation_depth,
        parent_delegation_id: params.parent_delegation_id,
        issued_at: now,
        metadata: params.metadata,
    };
    let jws = principal_signer.sign_payload(&payload)?;
    Ok(IssuedDelegation { jws, payload })
}
