//! Issuer Service for the Agent Authority Protocol.
//!
//! The only server component that registers users' devices. It never holds a
//! user private key: it verifies Apple App Attest evidence and a
//! proof-of-possession signature from the user's Secure Enclave key, and it
//! binds each later mandate to the attested app instance via an App Attest
//! assertion. No credential issuance yet (that is R2).

pub mod appattest;
pub mod config;
pub mod error;
pub mod http;
pub mod jwk;
pub mod migrate;
pub mod ratelimit;
pub mod service;
