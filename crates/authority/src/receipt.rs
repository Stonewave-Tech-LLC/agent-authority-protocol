//! AP2 Mandate Receipts (agent_authorization.md "Action Authorization"),
//! issued for every outcome, accept and reject alike (0004 V6).
//!
//! Claims: `iss` (the verifier), `iat`, `result` (`success` | `error`),
//! `reference` (hash of the final SD-JWT of the chain, computed like
//! `sd_hash` with that element's `_sd_alg`), `error` and
//! `error_description` on rejection, and AAP's `aap_chain`: the hash of
//! every element, root first, so a receipt pins the whole chain and not
//! only its last link.

use aap_sdjwt::{sign_jwt, Signer};
use serde_json::{json, Map, Value};

use crate::names::RECEIPT_TYP;

/// AP2's error codes, plus AAP's `insufficient_mandate` (0005: the verifier
/// requires more than the presented mandate kind allows).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    /// The mandate fails verification. Terminal.
    InvalidCredential,
    /// Unknown constraint, or the verifier cannot decide whether the closed
    /// mandate conforms. The agent may fall back to a directly approved
    /// closed mandate.
    UnresolvedConstraint,
    /// The mandate does not approve the requested action. Terminal.
    InvalidMandate,
    /// The verifier does not accept mandates for this action.
    MandatesNotSupported,
    /// The verifier's risk policy needs a stronger mandate kind (0005).
    InsufficientMandate,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::InvalidCredential => "invalid_credential",
            ErrorCode::UnresolvedConstraint => "unresolved_constraint",
            ErrorCode::InvalidMandate => "invalid_mandate",
            ErrorCode::MandatesNotSupported => "mandates_not_supported",
            ErrorCode::InsufficientMandate => "insufficient_mandate",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MandateReceipt {
    pub iss: String,
    pub iat: i64,
    pub reference: String,
    /// `None` on success.
    pub error: Option<(ErrorCode, String)>,
    pub aap_chain: Vec<String>,
}

impl MandateReceipt {
    pub fn result(&self) -> &'static str {
        if self.error.is_none() {
            "success"
        } else {
            "error"
        }
    }

    pub fn to_claims(&self) -> Map<String, Value> {
        let mut claims = Map::new();
        claims.insert("iss".into(), json!(self.iss));
        claims.insert("iat".into(), json!(self.iat));
        claims.insert("result".into(), json!(self.result()));
        claims.insert("reference".into(), json!(self.reference));
        if let Some((code, description)) = &self.error {
            claims.insert("error".into(), json!(code.as_str()));
            claims.insert("error_description".into(), json!(description));
        }
        claims.insert("aap_chain".into(), json!(self.aap_chain));
        claims
    }

    /// The receipt as a compact JWS signed by the verifier.
    pub fn sign<S: Signer + ?Sized>(&self, signer: &S) -> Result<String, aap_sdjwt::Error> {
        sign_jwt(RECEIPT_TYP, &Map::new(), &self.to_claims(), signer)
    }
}
