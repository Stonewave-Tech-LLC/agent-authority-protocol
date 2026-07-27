//! Signed audit receipts. `Verifier::verify` produces one on *every* call —
//! acceptance and rejection alike — because "this was correctly denied" is
//! as much a liability-relevant fact as "this was correctly granted". A
//! receipt is the durable, third-party-checkable artifact that answers
//! "who acted, under what authority, and what did the Verifier decide" after
//! the fact — the thing that turns a VerifiedAction from an in-memory
//! decision into evidence.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine as _};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ReceiptOutcome {
    Accepted,
    Rejected { reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    pub receipt_id: Uuid,
    pub verifier_id: String,
    /// Best-effort even on rejection: whatever could be determined about who
    /// was asking before the check that actually failed.
    pub agent_id: String,
    /// Leaf-first delegation ids that could be established. On acceptance
    /// this is the full, verified chain; on rejection it may be shorter —
    /// only as far as parsing/verification got before failing.
    pub delegation_ids: Vec<Uuid>,
    /// Digest of the presented agent message JWS, not the raw message —
    /// enough to prove *which* request this receipt is about without the
    /// receipt itself carrying potentially sensitive request payloads.
    pub request_digest: String,
    pub outcome: ReceiptOutcome,
    pub decided_at: DateTime<Utc>,
}

pub fn digest_request(agent_message_jws: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(agent_message_jws.as_bytes());
    format!("sha256:{}", B64.encode(hasher.finalize()))
}
