//! App Attest verification: the happy path and every rejection path, against
//! a synthetic Apple-style PKI (no device captures).

mod common;

use aap_issuer_service::appattest::*;
use common::*;
use sha2::{Digest, Sha256};

fn setup() -> (Pki, AppAttestDevice, Vec<String>, Vec<u8>) {
    (
        Pki::new(),
        AppAttestDevice::new(),
        vec![APP_ID.to_string()],
        Sha256::digest(b"client data").to_vec(),
    )
}

fn check(
    pki: &Pki,
    dev: &AppAttestDevice,
    ids: &[String],
    cdh: &[u8],
    o: &Opts,
    allow_dev: bool,
    now: i64,
) -> Result<AttestedKey, AppAttestError> {
    let att = attestation(pki, dev, cdh, o);
    verify_attestation_with_root(
        pki.root_pem(),
        &att,
        &dev.key_id,
        cdh,
        &Policy {
            app_ids: ids,
            allow_development: allow_dev,
        },
        now,
    )
}

#[test]
fn valid_production_attestation_is_accepted() {
    let (pki, dev, ids, cdh) = setup();
    let k = check(&pki, &dev, &ids, &cdh, &Opts::default(), false, NOW).unwrap();
    assert_eq!(k.environment, Environment::Production);
    assert_eq!(k.app_id, APP_ID);
    assert_eq!(
        k.public_key,
        dev.sk.verifying_key().to_encoded_point(false).as_bytes()
    );
}

#[test]
fn development_aaguid_needs_explicit_policy() {
    let (pki, dev, ids, cdh) = setup();
    assert_eq!(
        check(&pki, &dev, &ids, &cdh, &dev_opts(), false, NOW).err(),
        Some(AppAttestError::DevelopmentNotAccepted)
    );
    let k = check(&pki, &dev, &ids, &cdh, &dev_opts(), true, NOW).unwrap();
    assert_eq!(k.environment, Environment::Development);
}

#[test]
fn unknown_aaguid_is_rejected() {
    let (pki, dev, ids, cdh) = setup();
    let o = Opts {
        aaguid: [7; 16],
        ..Opts::default()
    };
    assert_eq!(
        check(&pki, &dev, &ids, &cdh, &o, true, NOW).err(),
        Some(AppAttestError::AaguidUnknown)
    );
}

#[test]
fn wrong_rp_id_hash_is_rejected() {
    let (pki, dev, ids, cdh) = setup();
    let o = Opts {
        app_id: OTHER_APP_ID.into(),
        ..Opts::default()
    };
    assert_eq!(
        check(&pki, &dev, &ids, &cdh, &o, false, NOW).err(),
        Some(AppAttestError::RpIdNotAllowed)
    );
}

#[test]
fn any_allow_listed_app_id_matches() {
    let (pki, dev, _, cdh) = setup();
    let ids = vec![APP_ID.to_string(), OTHER_APP_ID.to_string()];
    let o = Opts {
        app_id: OTHER_APP_ID.into(),
        ..Opts::default()
    };
    assert_eq!(
        check(&pki, &dev, &ids, &cdh, &o, false, NOW)
            .unwrap()
            .app_id,
        OTHER_APP_ID
    );
}

#[test]
fn wrong_nonce_is_rejected() {
    let (pki, dev, ids, cdh) = setup();
    let o = Opts {
        bad_nonce: true,
        ..Opts::default()
    };
    assert_eq!(
        check(&pki, &dev, &ids, &cdh, &o, false, NOW).err(),
        Some(AppAttestError::NonceMismatch)
    );
}

#[test]
fn client_data_hash_binding_is_enforced() {
    let (pki, dev, ids, cdh) = setup();
    let att = attestation(&pki, &dev, &cdh, &Opts::default());
    let other = Sha256::digest(b"different").to_vec();
    let r = verify_attestation_with_root(
        pki.root_pem(),
        &att,
        &dev.key_id,
        &other,
        &Policy {
            app_ids: &ids,
            allow_development: false,
        },
        NOW,
    );
    assert_eq!(r.err(), Some(AppAttestError::NonceMismatch));
}

#[test]
fn nonzero_counter_is_rejected() {
    let (pki, dev, ids, cdh) = setup();
    let o = Opts {
        counter: 1,
        ..Opts::default()
    };
    assert_eq!(
        check(&pki, &dev, &ids, &cdh, &o, false, NOW).err(),
        Some(AppAttestError::CounterNotZero)
    );
}

#[test]
fn credential_id_must_equal_key_id() {
    let (pki, dev, ids, cdh) = setup();
    let o = Opts {
        credential_id: Some(vec![1; 32]),
        ..Opts::default()
    };
    assert_eq!(
        check(&pki, &dev, &ids, &cdh, &o, false, NOW).err(),
        Some(AppAttestError::CredentialIdMismatch)
    );
}

#[test]
fn key_id_must_be_hash_of_the_credential_key() {
    let (pki, dev, ids, cdh) = setup();
    let att = attestation(&pki, &dev, &cdh, &Opts::default());
    let r = verify_attestation_with_root(
        pki.root_pem(),
        &att,
        &[9u8; 32],
        &cdh,
        &Policy {
            app_ids: &ids,
            allow_development: false,
        },
        NOW,
    );
    assert_eq!(r.err(), Some(AppAttestError::KeyIdMismatch));
}

#[test]
fn chain_to_a_different_root_is_rejected() {
    let (pki, dev, ids, cdh) = setup();
    let att = attestation(&pki, &dev, &cdh, &Opts::default());
    let impostor = Pki::new();
    let r = verify_attestation_with_root(
        impostor.root_pem(),
        &att,
        &dev.key_id,
        &cdh,
        &Policy {
            app_ids: &ids,
            allow_development: false,
        },
        NOW,
    );
    assert_eq!(r.err(), Some(AppAttestError::ChainInvalid));
}

#[test]
fn pinned_apple_root_rejects_a_synthetic_chain() {
    let (pki, dev, ids, cdh) = setup();
    let att = attestation(&pki, &dev, &cdh, &Opts::default());
    let r = verify_attestation(
        &att,
        &dev.key_id,
        &cdh,
        &Policy {
            app_ids: &ids,
            allow_development: true,
        },
        NOW,
    );
    assert_eq!(r.err(), Some(AppAttestError::ChainInvalid));
}

#[test]
fn leaf_that_is_a_ca_is_rejected() {
    let (pki, dev, ids, cdh) = setup();
    let o = Opts {
        leaf_is_ca: true,
        ..Opts::default()
    };
    assert_eq!(
        check(&pki, &dev, &ids, &cdh, &o, false, NOW).err(),
        Some(AppAttestError::ChainInvalid)
    );
}

#[test]
fn certificates_outside_validity_are_rejected() {
    let (pki, dev, ids, cdh) = setup();
    // 2103 and 1970 are both outside 2020..2100.
    assert_eq!(
        check(
            &pki,
            &dev,
            &ids,
            &cdh,
            &Opts::default(),
            false,
            4_200_000_000
        )
        .err(),
        Some(AppAttestError::CertExpired)
    );
    assert_eq!(
        check(&pki, &dev, &ids, &cdh, &Opts::default(), false, 0).err(),
        Some(AppAttestError::CertExpired)
    );
}

#[test]
fn structural_garbage_is_rejected_without_panicking() {
    let (pki, dev, ids, cdh) = setup();
    let p = Policy {
        app_ids: &ids,
        allow_development: false,
    };
    let v =
        |att: &[u8]| verify_attestation_with_root(pki.root_pem(), att, &dev.key_id, &cdh, &p, NOW);
    assert_eq!(v(b"").err(), Some(AppAttestError::Cbor));
    assert_eq!(v(&[0xff, 0x00]).err(), Some(AppAttestError::Cbor));
    assert_eq!(
        v(&cbor(&ciborium::value::Value::Integer(1.into()))).err(),
        Some(AppAttestError::Structure)
    );
    let o = Opts {
        fmt: "packed",
        ..Opts::default()
    };
    assert_eq!(
        v(&attestation(&pki, &dev, &cdh, &o)).err(),
        Some(AppAttestError::Format)
    );
    let o = Opts {
        x5c_len: 1,
        ..Opts::default()
    };
    assert_eq!(
        v(&attestation(&pki, &dev, &cdh, &o)).err(),
        Some(AppAttestError::Structure)
    );
}

// ---------------------------------------------------------------- assertions

fn att_key(dev: &AppAttestDevice) -> Vec<u8> {
    dev.sk
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec()
}

#[test]
fn valid_assertion_returns_its_counter() {
    let dev = AppAttestDevice::new();
    let digest = mandate_digest(b"mandate");
    let a = assertion(&dev, 7, &digest);
    assert_eq!(verify_assertion(&a, &digest, APP_ID, &att_key(&dev)), Ok(7));
}

#[test]
fn bare_37_byte_authenticator_data_with_at_flag_is_accepted() {
    // This is what iOS 27 produces; the flag must not be trusted or required.
    let d = assertion_auth_data(APP_ID, 3);
    assert_eq!(d.len(), 37);
    assert_eq!(d[32] & 0x40, 0x40);
    let dev = AppAttestDevice::new();
    let digest = mandate_digest(b"m");
    assert_eq!(
        verify_assertion(
            &assertion(&dev, 3, &digest),
            &digest,
            APP_ID,
            &att_key(&dev)
        ),
        Ok(3)
    );
}

#[test]
fn high_s_signatures_are_accepted() {
    let dev = AppAttestDevice::new();
    let digest = mandate_digest(b"m");
    for counter in 1..=20 {
        let a = assertion_with(&dev, APP_ID, counter, &digest, true);
        assert_eq!(
            verify_assertion(&a, &digest, APP_ID, &att_key(&dev)),
            Ok(counter)
        );
    }
}

#[test]
fn assertion_over_a_different_payload_is_rejected() {
    let dev = AppAttestDevice::new();
    let a = assertion(&dev, 1, &mandate_digest(b"signed"));
    assert_eq!(
        verify_assertion(&a, &mandate_digest(b"presented"), APP_ID, &att_key(&dev)).err(),
        Some(AppAttestError::BadSignature)
    );
}

#[test]
fn assertion_from_another_key_is_rejected() {
    let (dev, other) = (AppAttestDevice::new(), AppAttestDevice::new());
    let digest = mandate_digest(b"m");
    let a = assertion(&other, 1, &digest);
    assert_eq!(
        verify_assertion(&a, &digest, APP_ID, &att_key(&dev)).err(),
        Some(AppAttestError::BadSignature)
    );
}

#[test]
fn assertion_for_another_app_is_rejected() {
    let dev = AppAttestDevice::new();
    let digest = mandate_digest(b"m");
    let a = assertion_with(&dev, OTHER_APP_ID, 1, &digest, false);
    assert_eq!(
        verify_assertion(&a, &digest, APP_ID, &att_key(&dev)).err(),
        Some(AppAttestError::AssertionRpIdMismatch)
    );
}

#[test]
fn malformed_assertions_are_rejected() {
    let dev = AppAttestDevice::new();
    let d = mandate_digest(b"m");
    let k = att_key(&dev);
    assert_eq!(
        verify_assertion(b"", &d, APP_ID, &k).err(),
        Some(AppAttestError::Cbor)
    );
    assert_eq!(
        verify_assertion(&cbor(&ciborium::value::Value::Map(vec![])), &d, APP_ID, &k).err(),
        Some(AppAttestError::Structure)
    );
    assert_eq!(
        verify_assertion(&assertion(&dev, 1, &d), &d, APP_ID, &[4u8; 10]).err(),
        Some(AppAttestError::BadPublicKey)
    );
}

#[test]
fn the_high_s_helper_really_produces_high_s_signatures() {
    use p256::ecdsa::{signature::Signer, Signature};
    let dev = AppAttestDevice::new();
    for i in 0..10u8 {
        let sig: Signature = dev.sk.sign(&[i]);
        let hs = to_high_s(sig);
        assert!(hs.normalize_s().is_some(), "expected a high-S signature");
    }
}

/// Writes structurally valid seeds for the fuzz corpus:
/// `FUZZ_SEED_DIR=/some/dir cargo test --test attestation -- --ignored write_fuzz_seeds`
#[test]
#[ignore]
fn write_fuzz_seeds() {
    let Ok(dir) = std::env::var("FUZZ_SEED_DIR") else {
        return;
    };
    let (pki, dev) = (Pki::new(), AppAttestDevice::new());
    let cdh = Sha256::digest(b"seed").to_vec();
    let w = |sub: &str, name: &str, bytes: &[u8]| {
        let d = std::path::Path::new(&dir).join(sub);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join(name), bytes).unwrap();
    };
    w(
        "attestation",
        "valid",
        &attestation(&pki, &dev, &cdh, &Opts::default()),
    );
    w(
        "attestation",
        "development",
        &attestation(&pki, &dev, &cdh, &dev_opts()),
    );
    w("assertion", "valid", &assertion(&dev, 1, &cdh));
    w("auth_data", "assertion", &assertion_auth_data(APP_ID, 1));
    w(
        "auth_data",
        "attestation",
        &auth_data_attestation(&dev, &Opts::default()),
    );
    let (principal, challenge) = (Principal::new(), vec![3u8; 32]);
    let body =
        Enrollment::new(&pki, &dev, &principal, challenge).body(&uuid::Uuid::nil().to_string());
    w("requests", "enroll", body.to_string().as_bytes());
    let a = serde_json::json!({"device_id": uuid::Uuid::nil(), "payload_digest": "A".repeat(43), "assertion": "AAAA"});
    w("requests", "assertion", a.to_string().as_bytes());
}
