#![no_main]
//! Arbitrary attestation bytes against the pinned Apple root: exercises the
//! CBOR parser, x5c extraction and X.509 parsing. It must only ever return
//! an error, never panic.
use aap_issuer_service::appattest::{verify_attestation, Policy};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let ids = vec!["ABCDE12345.com.example.issuer".to_string()];
    let policy = Policy { app_ids: &ids, allow_development: true };
    let _ = verify_attestation(data, &[0u8; 32], &[0u8; 32], &policy, 1_800_000_000);
});
