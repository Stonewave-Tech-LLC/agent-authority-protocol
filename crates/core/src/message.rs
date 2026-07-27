//! Agent-side issuance: build and sign an `AgentMessage` requesting a
//! specific action against a specific Verifier (`audience`).

use chrono::Utc;
use uuid::Uuid;

use crate::jws::JwsError;
use crate::signer::Signer;
use crate::types::{ActionRequest, AgentMessage};

pub struct IssuedAgentMessage {
    pub jws: String,
    pub payload: AgentMessage,
}

pub fn issue(
    agent_signer: &impl Signer,
    agent_id: impl Into<String>,
    audience: impl Into<String>,
    request: ActionRequest,
) -> Result<IssuedAgentMessage, JwsError> {
    let payload = AgentMessage {
        agent_id: agent_id.into(),
        audience: audience.into(),
        nonce: Uuid::new_v4().to_string(),
        issued_at: Utc::now(),
        request,
    };
    let jws = agent_signer.sign_payload(&payload)?;
    Ok(IssuedAgentMessage { jws, payload })
}
