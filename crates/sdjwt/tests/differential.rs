//! Differential cross-check against `sd-jwt-payload` (IOTA), an independent,
//! maintained RFC 9901 implementation. It does not verify signatures, so
//! the comparison is on what both produce from the same bytes: the
//! processed payload, and the `sd_hash` a KB-JWT commits to. Tokens flow
//! both ways: ours decoded by it, its tokens verified by us.

mod common;

use aap_sdjwt::{
    typ, KeyBinding, LinkBuilder, Presentation, SdJwtBuilder, Signer, SigningKey, Unverified,
    VerifyOptions,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine as _};
use common::*;
use sd_jwt_payload::{
    Hasher as _, JwsSigner, KeyBindingJwtBuilder, RequiredKeyBinding, SdJwt as TheirSdJwt,
    SdJwtBuilder as TheirBuilder, Sha256Hasher,
};
use serde_json::{json, Map, Value};

/// Lets `sd-jwt-payload` sign with our keys.
struct TheirSigner(SigningKey);

#[async_trait::async_trait]
impl JwsSigner for TheirSigner {
    type Error = String;

    async fn sign(
        &self,
        header: &Map<String, Value>,
        payload: &Map<String, Value>,
    ) -> Result<Vec<u8>, String> {
        let input = format!(
            "{}.{}",
            B64.encode(serde_json::to_vec(header).unwrap()),
            B64.encode(serde_json::to_vec(payload).unwrap())
        );
        let sig = self.0.sign(input.as_bytes()).map_err(|e| e.to_string())?;
        Ok(format!("{input}.{}", B64.encode(sig)).into_bytes())
    }
}

fn theirs_decoded(sd_jwt: &str) -> Value {
    let parsed = TheirSdJwt::parse(sd_jwt).unwrap_or_else(|e| panic!("{e}: {sd_jwt}"));
    Value::Object(parsed.into_disclosed_object(&Sha256Hasher::new()).unwrap())
}

#[test]
fn both_implementations_process_every_rfc_vector_identically() {
    let kb = KeyBinding::KbJwt {
        audience: "https://verifier.example.org".into(),
        nonce: "1234567890".into(),
    };
    for (name, typ, key_binding) in [
        (
            "rfc9901_5_1_issued.txt",
            "example+sd-jwt",
            KeyBinding::NotRequired,
        ),
        ("rfc9901_5_2_presentation.txt", "example+sd-jwt", kb.clone()),
        (
            "rfc9901_a1_presentation.txt",
            "example+sd-jwt",
            KeyBinding::NotRequired,
        ),
        (
            "rfc9901_a2_presentation.txt",
            "example+sd-jwt",
            KeyBinding::NotRequired,
        ),
        (
            "rfc9901_a3_issued.txt",
            "dc+sd-jwt",
            KeyBinding::NotRequired,
        ),
        ("rfc9901_a3_presentation.txt", "dc+sd-jwt", kb.clone()),
        (
            "rfc9901_a4_issued.txt",
            "example+sd-jwt",
            KeyBinding::NotRequired,
        ),
        ("rfc9901_a4_presentation.txt", "example+sd-jwt", kb.clone()),
    ] {
        let s = vector(name);
        let mut options = VerifyOptions::new(1_748_537_254, typ, key_binding);
        options.require_exp = false;
        let ours = verify(&s, &rfc_issuer_key(), &options).unwrap();
        assert_eq!(
            Value::Object(ours.root().claims().clone()),
            theirs_decoded(&s),
            "{name}"
        );
    }
}

fn rich_claims(holder: &SigningKey) -> Map<String, Value> {
    obj(json!({
        "iss": "https://issuer.aap.example",
        "iat": NOW - 10,
        "exp": NOW + 3600,
        "sub": "user_42",
        "email": "ada@example.com",
        "address": {"street": "12 Main St", "locality": "Wien", "country": "AT"},
        "nationalities": ["AT", "DE", "IT"],
        "nested": {"deep": {"value": [1, {"x": "y"}, null]}},
        "emoji": "🔐 ü",
        "cnf": holder.verifying_key().to_cnf(),
    }))
}

#[test]
fn our_tokens_decode_identically_in_theirs() {
    let issuer = SigningKey::generate_p256();
    let holder = SigningKey::generate_p256();
    let claims = rich_claims(&holder);
    let issued = SdJwtBuilder::new(typ::SD_JWT_VC, claims.clone())
        .conceal("/email")
        .conceal("/address/street")
        .conceal("/address")
        .conceal("/nationalities/0")
        .conceal("/nationalities/2")
        .conceal("/nationalities")
        .conceal("/nested/deep/value/1/x")
        .conceal("/nested/deep/value/1")
        .conceal("/emoji")
        .decoys("", 3)
        .decoys("/nationalities", 2)
        .sign(&issuer)
        .unwrap();

    // Everything disclosed: both recover the original claims exactly.
    let full = Presentation::new(issued.clone()).serialize();
    assert_eq!(theirs_decoded(&full), Value::Object(claims));

    // A selection, key-bound by us; both agree on the result and on sd_hash.
    let presented = Presentation::new(issued)
        .select(
            0,
            &[
                "/address/locality",
                "/nationalities/1",
                "/nested/deep/value/1/x",
            ],
        )
        .unwrap()
        .bind(&binding(VERIFIER, CHALLENGE, NOW), &holder)
        .unwrap()
        .serialize();
    let ours = verify(&presented, &issuer.verifying_key(), &kb_options()).unwrap();
    assert_eq!(
        Value::Object(ours.root().claims().clone()),
        theirs_decoded(&presented)
    );
    assert_eq!(ours.root().claims()["nationalities"], json!(["DE"]));
    assert!(ours.root().claims().get("email").is_none());

    let theirs = TheirSdJwt::parse(&presented).unwrap();
    let their_sd_hash = theirs.key_binding_jwt().unwrap().claims().sd_hash.clone();
    let (without_kb, _) = presented.rsplit_once('~').unwrap();
    assert_eq!(
        Sha256Hasher::new().encoded_digest(&format!("{without_kb}~")),
        their_sd_hash
    );
}

#[test]
fn their_tokens_verify_in_ours() {
    let issuer = SigningKey::generate_p256();
    let holder = SigningKey::generate_p256();
    let mut claims = rich_claims(&holder);
    let cnf_jwk = claims.remove("cnf").unwrap()["jwk"]
        .as_object()
        .unwrap()
        .clone();
    let hasher = Sha256Hasher::new();

    let issued = pollster::block_on(
        TheirBuilder::new(Value::Object(claims.clone()))
            .unwrap()
            .header("typ", typ::SD_JWT_VC)
            .make_concealable("/email")
            .unwrap()
            .make_concealable("/address/street")
            .unwrap()
            .make_concealable("/address")
            .unwrap()
            .make_concealable("/nationalities/1")
            .unwrap()
            .make_concealable("/emoji")
            .unwrap()
            .add_decoys("", 2)
            .unwrap()
            .require_key_binding(RequiredKeyBinding::Jwk(cnf_jwk.clone()))
            .finish(&TheirSigner(issuer.clone()), "ES256"),
    )
    .unwrap();

    // Issued as-is: our holder-side check accepts it and agrees on content.
    let issued_str = issued.presentation();
    let options = VerifyOptions::new(NOW, typ::SD_JWT_VC, KeyBinding::NotRequired);
    let ours = verify(&issued_str, &issuer.verifying_key(), &options).unwrap();
    let mut expected = claims;
    expected.insert("cnf".into(), json!({ "jwk": cnf_jwk }));
    assert_eq!(
        Value::Object(ours.root().claims().clone()),
        Value::Object(expected)
    );

    // Their holder conceals two claims and adds their KB-JWT; we verify it.
    let (mut presented, _) = issued
        .into_presentation(&hasher)
        .unwrap()
        .conceal("/email")
        .unwrap()
        .conceal("/nationalities/1")
        .unwrap()
        .finish();
    let kb = pollster::block_on(
        KeyBindingJwtBuilder::new()
            .iat(NOW)
            .aud(VERIFIER)
            .nonce(CHALLENGE)
            .finish(&presented, &hasher, "ES256", &TheirSigner(holder.clone())),
    )
    .unwrap();
    presented.attach_key_binding_jwt(kb);
    let presented = presented.presentation();
    let ours = verify(&presented, &issuer.verifying_key(), &kb_options()).unwrap();
    assert_eq!(
        Value::Object(ours.root().claims().clone()),
        theirs_decoded(&presented)
    );
    assert!(ours.root().claims().get("email").is_none());
    assert_eq!(ours.root().claims()["nationalities"], json!(["AT", "IT"]));
}

#[test]
fn each_chain_element_is_an_sd_jwt_they_decode_identically() {
    // `sd-jwt-payload` knows nothing of delegation, but every element of a
    // Delegate SD-JWT chain is itself an RFC 9901 SD-JWT. Its processed
    // payload must match our envelope plus the one disclosed Delegate
    // Payload.
    let parties = Parties::new();
    let presentation = parties.closed();
    let chain = verify(
        &presentation,
        &parties.issuer.verifying_key(),
        &terminal_options(),
    )
    .unwrap();
    assert_eq!(
        Value::Object(chain.root().claims().clone()),
        theirs_decoded(chain.root().sd_jwt())
    );
    for link in chain.delegations() {
        let mut ours = link.envelope().clone();
        ours.insert("delegate_payload".into(), json!([link.claims()]));
        assert_eq!(Value::Object(ours), theirs_decoded(link.sd_jwt()));
    }

    // And a link with several Delegate Payloads, one presented.
    let delegated = Presentation::new(user_credential(
        &parties.issuer,
        &parties.user.verifying_key(),
    ))
    .delegate(
        LinkBuilder::new(open_mandate(&parties.agent.verifying_key()))
            .add_payload(open_mandate(&parties.agent.verifying_key())),
        &binding("a", "n", NOW),
        &parties.user,
    )
    .unwrap()
    .select(1, &["/delegate_payload/1/constraints/0/allowed/2"])
    .unwrap();
    let link = delegated.links()[0].serialize();
    let decoded = theirs_decoded(&link);
    assert_eq!(decoded["delegate_payload"].as_array().unwrap().len(), 1);
    assert_eq!(
        decoded["delegate_payload"][0]["constraints"][0]["allowed"],
        json!([{"id": "merchant_3", "website": "https://third.example"}])
    );
    let presented = delegated
        .bind(&binding(VERIFIER, CHALLENGE, NOW), &parties.agent)
        .unwrap()
        .serialize();
    let chain = Unverified::<Presentation>::parse(&presented)
        .unwrap()
        .verify(&parties.issuer.verifying_key(), &kb_options())
        .unwrap();
    assert_eq!(
        Value::Object(chain.delegations()[0].claims().clone()),
        decoded["delegate_payload"][0]
    );
}
