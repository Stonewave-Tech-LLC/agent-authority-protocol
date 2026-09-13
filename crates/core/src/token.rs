//! Typestate wrappers for signed data. `Unverified<...>` and `Verified<...>`
//! are distinct Rust types — the only way to obtain a `Verified` token is
//! `verify_signature()` succeeding. Every function in `verifier.rs` that
//! grants authority takes `Verified` tokens as arguments, so "an unverified
//! delegation was treated as verified" is a compile error, not a runtime bug
//! to be caught by tests or code review.

use std::marker::PhantomData;

use uuid::Uuid;

use crate::jws::{self, JwsError};
use crate::keys::VerifyingKey;
use crate::types::{AgentMessage, Delegation};

pub struct Unverified;
pub struct Verified;

pub struct DelegationToken<State = Unverified> {
    pub jws: String,
    pub payload: Delegation,
    _state: PhantomData<State>,
}

impl DelegationToken<Unverified> {
    /// Decodes the payload without checking the signature. The result is
    /// only safe to inspect for routing purposes (e.g. "which principal do
    /// I need to resolve a key for?") — never as a basis for authorization.
    pub fn from_jws(jws: impl Into<String>) -> Result<Self, JwsError> {
        let jws = jws.into();
        let payload: Delegation = jws::decode_unverified(&jws)?;
        Ok(Self {
            jws,
            payload,
            _state: PhantomData,
        })
    }

    pub fn verify_signature(
        self,
        principal_key: &VerifyingKey,
    ) -> Result<DelegationToken<Verified>, JwsError> {
        let payload: Delegation = jws::verify(&self.jws, principal_key)?;
        Ok(DelegationToken {
            jws: self.jws,
            payload,
            _state: PhantomData,
        })
    }
}

impl<State> DelegationToken<State> {
    pub fn delegation_id(&self) -> Uuid {
        self.payload.delegation_id
    }
}

pub struct AgentMessageToken<State = Unverified> {
    pub jws: String,
    pub payload: AgentMessage,
    _state: PhantomData<State>,
}

impl AgentMessageToken<Unverified> {
    pub fn from_jws(jws: impl Into<String>) -> Result<Self, JwsError> {
        let jws = jws.into();
        let payload: AgentMessage = jws::decode_unverified(&jws)?;
        Ok(Self {
            jws,
            payload,
            _state: PhantomData,
        })
    }

    pub fn verify_signature(
        self,
        agent_key: &VerifyingKey,
    ) -> Result<AgentMessageToken<Verified>, JwsError> {
        let payload: AgentMessage = jws::verify(&self.jws, agent_key)?;
        Ok(AgentMessageToken {
            jws: self.jws,
            payload,
            _state: PhantomData,
        })
    }
}
