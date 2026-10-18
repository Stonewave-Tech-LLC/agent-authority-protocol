//! SD-JWT (RFC 9901), key binding, and Delegate SD-JWT chains
//! (draft-gco-oauth-delegate-sd-jwt) for the Agent Authority Protocol.
//!
//! Format only, no policy: this crate proves that a presentation is a
//! correctly signed, correctly chained, correctly disclosed SD-JWT or
//! Delegate SD-JWT, and hands the claims of every link to the caller as a
//! [`VerifiedChain`]. What those claims *permit* is decided elsewhere
//! (`aap-core`), on the `VerifiedChain` only.
//!
//! Hand-rolled on purpose, like `aap-core`'s JWS: SD-JWT is salted hashes
//! plus JWS, and a small, auditable trust path matters more than reuse. An
//! independent RFC 9901 crate cross-checks this one in the tests.
//!
//! ```text
//! Issuer   SdJwtBuilder::sign            -> SdJwt (all disclosures)
//! Holder   Presentation::new(sd_jwt)
//!            .select(0, &["/given_name"])  choose what to reveal
//!            .delegate(link, &claims, key) KB-SD-JWT for an agent (optional, repeatable)
//!            .bind(&claims, key)           final KB-JWT (or end with a terminal link)
//!            .serialize()
//! Verifier Unverified::<Presentation>::parse(s)?.verify(&issuer_key, &options)? -> VerifiedChain
//! ```

#![forbid(unsafe_code)]

mod conceal;
mod disclosure;
mod error;
mod hash;
mod jws;
mod keys;
mod pointer;
mod presentation;
mod process;
mod sdjwt;
mod verify;

pub use conceal::SdPayload;
pub use disclosure::Disclosure;
pub use error::{Error, ErrorKind, Position};
pub use hash::SdAlg;
pub use keys::{Algorithm, Signer, SigningKey, VerifyingKey};
pub use presentation::Presentation;
pub use sdjwt::{BindingClaims, HashBinding, LinkBuilder, SdJwt, SdJwtBuilder};
pub use verify::{
    KeyBinding, LinkKind, Unverified, VerifiedChain, VerifiedKeyBinding, VerifiedLink,
    VerifyOptions,
};

/// JOSE `typ` values, checked per position in a presentation.
pub mod typ {
    /// An SD-JWT VC (the root user credential).
    pub const SD_JWT_VC: &str = "dc+sd-jwt";
    /// The final Key Binding JWT (RFC 9901 §4.3).
    pub const KB_JWT: &str = "kb+jwt";
    /// A KB-SD-JWT that does not delegate further (a closed mandate).
    pub const KB_SD_JWT: &str = "kb+sd-jwt";
    /// A KB-SD-JWT+KB: delegates to the `cnf` in its Delegate Payload.
    pub const KB_SD_JWT_KB: &str = "kb-sd-jwt+kb";
    /// The draft-00 spelling of [`KB_SD_JWT_KB`], renamed in draft-01 and
    /// still emitted by the AP2 reference SDK. Accepted, never produced.
    pub const KB_SD_JWT_KB_DRAFT_00: &str = "kb+sd-jwt+kb";
}
