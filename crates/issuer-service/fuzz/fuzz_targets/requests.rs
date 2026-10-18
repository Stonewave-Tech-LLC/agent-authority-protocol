#![no_main]
//! Untrusted JSON bodies for the enrollment and assertion endpoints.
use aap_issuer_service::service::{parse_assertion_request, parse_enroll_request};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = parse_enroll_request(data);
    let _ = parse_assertion_request(data);
});
