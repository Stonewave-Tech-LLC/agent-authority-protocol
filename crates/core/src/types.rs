use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalType {
    NaturalPerson,
    LegalEntity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Weekday {
    Mon,
    Tue,
    Wed,
    Thu,
    Fri,
    Sat,
    Sun,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TimeWindow {
    pub days: Vec<Weekday>,
    /// "HH:MM", 24h
    pub start: String,
    /// "HH:MM", 24h
    pub end: String,
    /// IANA timezone name, e.g. "Europe/Vienna"
    pub timezone: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Amount {
    pub value: f64,
    pub currency: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Counterparties {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny: Option<Vec<String>>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Scope {
    pub actions: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_amount: Option<Amount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counterparties: Option<Counterparties>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_categories: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_windows: Option<Vec<TimeWindow>>,
}

/// Ed25519 public key, JWK-ish shape (x = base64url raw 32 bytes).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PublicKeyJwk {
    pub kty: String, // "OKP"
    pub crv: String, // "Ed25519"
    pub x: String,   // base64url, no padding
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Delegation {
    pub delegation_id: Uuid,
    pub principal_id: String,
    pub principal_type: PrincipalType,
    pub agent_id: String,
    pub agent_public_key: PublicKeyJwk,
    pub scope: Scope,
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub status_endpoint: String,
    #[serde(default)]
    pub can_delegate: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_delegation_depth: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_delegation_id: Option<Uuid>,
    pub issued_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ActionRequest {
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount: Option<Amount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counterparty: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_categories: Option<Vec<String>>,
    pub timestamp: DateTime<Utc>,
}

/// Payload an Agent signs when presenting a request to a Verifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentMessage {
    pub agent_id: String,
    /// Identifies the intended Verifier. Prevents a signed request for
    /// Verifier A from being replayed against Verifier B.
    pub audience: String,
    pub nonce: String,
    pub issued_at: DateTime<Utc>,
    pub request: ActionRequest,
}

#[derive(Debug, thiserror::Error)]
pub enum VerificationFailure {
    #[error("delegation signature invalid")]
    InvalidDelegationSignature,
    #[error("agent message signature invalid")]
    InvalidAgentSignature,
    #[error("message audience does not match this verifier")]
    AudienceMismatch,
    #[error("nonce already used (possible replay)")]
    NonceReplayed,
    #[error("delegation not yet valid (valid_from in the future)")]
    NotYetValid,
    #[error("delegation expired")]
    Expired,
    #[error("delegation revoked")]
    Revoked,
    #[error("status endpoint check failed: {0}")]
    StatusCheckFailed(String),
    #[error("delegation chain broken: {0}")]
    ChainBroken(String),
    #[error("delegation chain exceeds max depth")]
    ChainTooDeep,
    #[error("sub-delegation scope is not a narrowing of its parent")]
    ScopeNotNarrowed,
    #[error("requested action is outside the delegated scope")]
    ScopeDenied,
    #[error("principal key could not be resolved: {0}")]
    KeyResolutionFailed(String),
}
