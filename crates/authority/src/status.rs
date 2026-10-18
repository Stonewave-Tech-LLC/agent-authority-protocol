//! Revocation status (0004 V2). Every element of a chain that carries a
//! `status` claim (a reference into an IETF Token Status List) is checked
//! through a [`StatusChecker`]. Anything other than an affirmative "valid"
//! rejects: a list that cannot be fetched, with no fresh cached copy, fails
//! closed.
//!
//! Elements without `status` are the agent-signed links of 0005 CG15:
//! agents run no status list, so such a link is accepted only if it expires
//! soon (`Policy::max_validity_without_status`).

use serde_json::Value;
use thiserror::Error;

/// The Token Status List values this crate distinguishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenStatus {
    Valid,
    Invalid,
    Suspended,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("status unavailable: {0}")]
pub struct StatusError(pub String);

pub trait StatusChecker {
    /// Resolves `status` (the claim's value, e.g. `{"status_list": {"idx":
    /// 7, "uri": "https://..."}}`) at the verifier's time `now`. The
    /// implementation owns fetching, caching and cache freshness (0005
    /// requires fresher status for higher risk classes).
    fn check(&self, status: &Value, now: i64) -> Result<TokenStatus, StatusError>;
}

/// For verifiers without a status list: every `status` claim fails, so a
/// revocable credential is never accepted unchecked.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoStatusList;

impl StatusChecker for NoStatusList {
    fn check(&self, _: &Value, _: i64) -> Result<TokenStatus, StatusError> {
        Err(StatusError("this verifier has no status list".into()))
    }
}
