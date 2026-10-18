#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = aap_issuer_service::appattest::parse_auth_data(data);
});
