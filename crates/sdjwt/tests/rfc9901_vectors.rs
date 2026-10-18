//! The example tokens of RFC 9901, verified byte for byte as published.
//! Every Issuer signature is checked against the Appendix A.5 key and every
//! KB-JWT against the `cnf` key in its SD-JWT.

mod common;

use std::collections::BTreeSet;

use aap_sdjwt::{KeyBinding, Presentation, Unverified, VerifyOptions};
use common::{rfc_issuer_key, vector, vector_json};
use serde_json::{json, Value};

/// The KB-JWTs in the RFC were created at this time.
const KB_IAT: i64 = 1_748_537_244;

fn rfc_kb() -> KeyBinding {
    KeyBinding::KbJwt {
        audience: "https://verifier.example.org".into(),
        nonce: "1234567890".into(),
    }
}

fn options(typ: &str, key_binding: KeyBinding) -> VerifyOptions {
    VerifyOptions::new(KB_IAT + 10, typ, key_binding)
}

fn verified_claims(name: &str, opts: &VerifyOptions) -> Value {
    let chain = Unverified::<Presentation>::parse(&vector(name))
        .unwrap()
        .verify(&rfc_issuer_key(), opts)
        .unwrap_or_else(|e| panic!("{name}: {e}"));
    assert!(chain.delegations().is_empty());
    Value::Object(chain.root().claims().clone())
}

fn disclosure_set(p: &Presentation) -> BTreeSet<String> {
    p.root()
        .disclosures()
        .iter()
        .map(|d| d.encoded().to_owned())
        .collect()
}

#[test]
fn section_5_1_issued_sd_jwt() {
    let opts = options("example+sd-jwt", KeyBinding::NotRequired);
    let claims = verified_claims("rfc9901_5_1_issued.txt", &opts);
    assert_eq!(
        claims,
        json!({
            "iss": "https://issuer.example.com",
            "iat": 1683000000,
            "exp": 1883000000,
            "sub": "user_42",
            "given_name": "John",
            "family_name": "Doe",
            "email": "johndoe@example.com",
            "phone_number": "+1-202-555-0101",
            "phone_number_verified": true,
            "address": {
                "street_address": "123 Main St",
                "locality": "Anytown",
                "region": "Anystate",
                "country": "US"
            },
            "birthdate": "1940-01-01",
            "updated_at": 1570000000,
            "nationalities": ["US", "DE"],
            "cnf": {
                "jwk": {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": "TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc",
                    "y": "ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ"
                }
            }
        })
    );
}

#[test]
fn section_5_1_disclosure_digests() {
    let p = Unverified::<Presentation>::parse(&vector("rfc9901_5_1_issued.txt"))
        .unwrap()
        .into_inner();
    let alg = p.root().sd_alg().unwrap();
    let by_name: Vec<(Option<&str>, String)> = p
        .root()
        .disclosures()
        .iter()
        .map(|d| (d.name(), d.digest(alg)))
        .collect();
    for (name, digest) in [
        (
            Some("given_name"),
            "jsu9yVulwQQlhFlM_3JlzMaSFzglhQG0DpfayQwLUK4",
        ),
        (
            Some("family_name"),
            "TGf4oLbgwd5JQaHyKVQZU9UdGE0w5rtDsrZzfUaomLo",
        ),
        (
            Some("address"),
            "XzFrzwscM6Gn6CJDc6vVK8BkMnfG8vOSKfpPIZdAfdE",
        ),
        (
            Some("updated_at"),
            "CrQe7S5kqBAHt-nMYXgc6bdt2SH5aTY1sU_M-PgkjPI",
        ),
        (None, "pFndjkZ_VCzmyTa6UjlZo3dh-ko8aIKQc9DlGzhaVYo"),
        (None, "7Cf6JkPudry3lcbwHgeZ8khAv1U1OSlerP0VkBJrWZ0"),
    ] {
        assert!(
            by_name.contains(&(name, digest.to_owned())),
            "{name:?} {digest}"
        );
    }
}

#[test]
fn section_5_2_sd_jwt_kb() {
    let claims = verified_claims(
        "rfc9901_5_2_presentation.txt",
        &options("example+sd-jwt", rfc_kb()),
    );
    assert_eq!(claims, vector_json("rfc9901_5_2_processed.json"));
}

#[test]
fn section_5_2_key_binding_claims_are_exposed() {
    let chain = Unverified::<Presentation>::parse(&vector("rfc9901_5_2_presentation.txt"))
        .unwrap()
        .verify(&rfc_issuer_key(), &options("example+sd-jwt", rfc_kb()))
        .unwrap();
    let kb = chain.key_binding().unwrap();
    assert_eq!(
        Value::Object(kb.claims().clone()),
        json!({
            "nonce": "1234567890",
            "aud": "https://verifier.example.org",
            "iat": 1748537244,
            "sd_hash": "0_Af-2B-EhLWX5ydh_w2xzwmO6iM66B_2QCEanI4fUY"
        })
    );
}

#[test]
fn holder_selection_reproduces_the_section_5_2_disclosures() {
    let issued = Unverified::<Presentation>::parse(&vector("rfc9901_5_1_issued.txt"))
        .unwrap()
        .into_inner();
    let selected = issued
        .select(
            0,
            &[
                "/family_name",
                "/address",
                "/given_name",
                "/nationalities/0",
            ],
        )
        .unwrap();
    let rfc = Unverified::<Presentation>::parse(&vector("rfc9901_5_2_presentation.txt"))
        .unwrap()
        .into_inner();
    assert_eq!(disclosure_set(&selected), disclosure_set(&rfc));
}

#[test]
fn appendix_a1_structured_presentation() {
    let claims = verified_claims(
        "rfc9901_a1_presentation.txt",
        &options("example+sd-jwt", KeyBinding::NotRequired),
    );
    assert_eq!(claims, vector_json("rfc9901_a1_processed.json"));
}

#[test]
fn appendix_a2_complex_structured_presentation() {
    let claims = verified_claims(
        "rfc9901_a2_presentation.txt",
        &options("example+sd-jwt", KeyBinding::NotRequired),
    );
    assert_eq!(claims, vector_json("rfc9901_a2_processed.json"));
}

#[test]
fn appendix_a3_sd_jwt_vc_issued_and_presented() {
    let issued = verified_claims(
        "rfc9901_a3_issued.txt",
        &options("dc+sd-jwt", KeyBinding::NotRequired),
    );
    assert_eq!(issued["vct"], "urn:eudi:pid:de:1");
    assert_eq!(issued["age_equal_or_over"]["18"], true);
    assert_eq!(issued["address"]["locality"], "Köln");

    let presented = verified_claims(
        "rfc9901_a3_presentation.txt",
        &options("dc+sd-jwt", rfc_kb()),
    );
    assert_eq!(presented, vector_json("rfc9901_a3_processed.json"));
}

#[test]
fn appendix_a4_w3c_vcdm_issued_and_presented() {
    // This credential carries its validity in `expirationDate`, not `exp`.
    let mut opts = options("example+sd-jwt", KeyBinding::NotRequired);
    opts.require_exp = false;
    let issued = verified_claims("rfc9901_a4_issued.txt", &opts);
    assert_eq!(issued["credentialSubject"]["recipient"]["gender"], "Female");

    let mut opts = options("example+sd-jwt", rfc_kb());
    opts.require_exp = false;
    let presented = verified_claims("rfc9901_a4_presentation.txt", &opts);
    assert_eq!(presented, vector_json("rfc9901_a4_processed.json"));
}

#[test]
fn every_vector_survives_a_parse_serialize_round_trip() {
    for name in [
        "rfc9901_5_1_issued.txt",
        "rfc9901_5_2_presentation.txt",
        "rfc9901_a1_presentation.txt",
        "rfc9901_a2_presentation.txt",
        "rfc9901_a3_issued.txt",
        "rfc9901_a3_presentation.txt",
        "rfc9901_a4_issued.txt",
        "rfc9901_a4_presentation.txt",
    ] {
        let s = vector(name);
        let p = Unverified::<Presentation>::parse(&s).unwrap().into_inner();
        assert_eq!(p.serialize(), s, "{name}");
    }
}
