//! One error type for parsing, issuance and verification. Verification
//! errors carry the [`Position`] in the presentation where they happened, so
//! a rejected chain says *which* link failed, not just that something did.

use std::fmt;

use thiserror::Error;

/// Where in a presentation an error was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Position {
    /// The Issuer-signed JWT and its disclosures.
    Root,
    /// The n-th KB-SD-JWT, counted from 1. Link 1 is signed with the root's
    /// `cnf` key, link 2 with link 1's, and so on.
    Link(usize),
    /// The final KB-JWT (`typ: kb+jwt`).
    KeyBinding,
}

impl fmt::Display for Position {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Position::Root => f.write_str("root"),
            Position::Link(n) => write!(f, "link {n}"),
            Position::KeyBinding => f.write_str("key binding JWT"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ErrorKind {
    #[error("malformed serialization: {0}")]
    Malformed(&'static str),
    #[error("invalid base64url")]
    Base64,
    #[error("invalid JSON: {0}")]
    Json(String),
    #[error("unsupported or forbidden JOSE header: {0}")]
    UnsupportedHeader(String),
    #[error("alg header {found:?} does not match the key's algorithm {expected}")]
    AlgorithmMismatch {
        expected: &'static str,
        found: Option<String>,
    },
    #[error("signature verification failed")]
    BadSignature,
    #[error("typ header {found:?} not allowed here (expected one of {expected:?})")]
    WrongTyp {
        expected: Vec<String>,
        found: Option<String>,
    },
    #[error("unsupported _sd_alg {0:?}")]
    UnsupportedSdAlg(String),
    #[error("invalid disclosure: {0}")]
    InvalidDisclosure(String),
    #[error("disclosure is not referenced by any digest")]
    UnreferencedDisclosure,
    #[error("the same disclosure is sent more than once")]
    DuplicateDisclosure,
    #[error("digest {0} appears more than once")]
    DuplicateDigest(String),
    #[error("disclosed claim {0:?} already exists at its level")]
    ClaimCollision(String),
    #[error("reserved name {0:?} used outside its purpose")]
    ReservedName(String),
    #[error("missing or invalid claim {0:?}")]
    InvalidClaim(&'static str),
    #[error("cnf is required here but missing")]
    MissingCnf,
    #[error("a terminal (kb+sd-jwt) link must not carry cnf")]
    UnexpectedCnf,
    #[error("unsupported or invalid key: {0}")]
    BadKey(String),
    #[error("{0} does not match the preceding element")]
    BindingMismatch(&'static str),
    #[error("exactly one of sd_hash and issuer_jwt_hash is required")]
    AmbiguousBinding,
    #[error("delegate_payload: {0}")]
    DelegatePayload(&'static str),
    #[error("expired")]
    Expired,
    #[error("not yet valid")]
    NotYetValid,
    #[error("exp is required but missing")]
    MissingExp,
    #[error("iat outside the acceptable window")]
    IatOutOfWindow,
    #[error("aud does not match the expected audience")]
    AudienceMismatch,
    #[error("nonce does not match the expected nonce")]
    NonceMismatch,
    #[error("key binding is required but the presentation has none")]
    MissingKeyBinding,
    #[error("the presentation carries a key binding JWT the verifier does not expect")]
    UnexpectedKeyBinding,
    #[error("invalid or unresolvable JSON pointer {0:?}")]
    InvalidPointer(String),
    #[error("signing failed: {0}")]
    Signing(String),
    #[error("cannot build token: {0}")]
    Issuance(&'static str),
}

impl ErrorKind {
    pub(crate) fn at(self, position: Position) -> Error {
        Error {
            position: Some(position),
            kind: self,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    position: Option<Position>,
    kind: ErrorKind,
}

impl Error {
    pub fn kind(&self) -> &ErrorKind {
        &self.kind
    }

    pub fn position(&self) -> Option<Position> {
        self.position
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Error {
            position: None,
            kind,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.position {
            Some(p) => write!(f, "{p}: {}", self.kind),
            None => write!(f, "{}", self.kind),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.kind)
    }
}
