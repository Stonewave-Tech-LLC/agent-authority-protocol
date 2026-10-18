//! Every documented way to break a presentation must fail, with the error
//! and the position the verifier reports pinned down.

mod common;

use aap_sdjwt::{
    typ, ErrorKind, KeyBinding, LinkBuilder, Position, Presentation, SigningKey, Unverified,
    VerifyOptions,
};
use common::*;
use serde_json::json;

fn expect_err(
    presentation: &str,
    issuer: &aap_sdjwt::VerifyingKey,
    options: &VerifyOptions,
) -> aap_sdjwt::Error {
    match verify(presentation, issuer, options) {
        Ok(_) => panic!("verification unexpectedly succeeded"),
        Err(e) => e,
    }
}

fn assert_fails(
    presentation: &str,
    issuer: &aap_sdjwt::VerifyingKey,
    options: &VerifyOptions,
    kind: ErrorKind,
    position: Option<Position>,
) {
    let err = expect_err(presentation, issuer, options);
    assert_eq!((err.kind(), err.position()), (&kind, position), "{err}");
}

fn rfc_kb_options() -> VerifyOptions {
    VerifyOptions::new(
        1_748_537_254,
        "example+sd-jwt",
        KeyBinding::KbJwt {
            audience: "https://verifier.example.org".into(),
            nonce: "1234567890".into(),
        },
    )
}

/// Replaces component `index` of a `~`-separated presentation.
fn replace_component(presentation: &str, index: usize, with: &str) -> String {
    let mut parts: Vec<&str> = presentation.split('~').collect();
    parts[index] = with;
    parts.join("~")
}

// --- Disclosures -----------------------------------------------------------

#[test]
fn tampered_disclosure_in_the_root() {
    let rfc = vector("rfc9901_5_2_presentation.txt");
    let original = rfc.split('~').nth(1).unwrap();
    // family_name "Doe" -> "Dow": still a valid disclosure, different digest.
    let decoded = String::from_utf8(
        base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, original)
            .unwrap(),
    )
    .unwrap();
    let tampered = b64(&decoded.replace("Doe", "Dow"));
    assert_fails(
        &replace_component(&rfc, 1, &tampered),
        &rfc_issuer_key(),
        &rfc_kb_options(),
        ErrorKind::UnreferencedDisclosure,
        Some(Position::Root),
    );
}

#[test]
fn tampered_disclosure_in_a_link() {
    let parties = Parties::new();
    let presentation = parties.closed();
    let components: Vec<&str> = presentation.split('~').collect();
    // The open mandate's merchant disclosure: the second disclosure of link 1.
    let link1 = components.iter().position(|c| c.is_empty()).unwrap() + 1;
    let merchant = components[link1 + 2];
    let decoded = String::from_utf8(
        base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, merchant)
            .unwrap(),
    )
    .unwrap();
    assert!(decoded.contains("merchant_1"), "{decoded}");
    let swapped = b64(&decoded.replace("merchant_1", "merchant_9"));
    assert_fails(
        &replace_component(&presentation, link1 + 2, &swapped),
        &parties.issuer.verifying_key(),
        &terminal_options(),
        ErrorKind::UnreferencedDisclosure,
        Some(Position::Link(1)),
    );
}

#[test]
fn extra_disclosure_after_the_key_binding_was_made() {
    // The KB-JWT's sd_hash covered four disclosures; adding a fifth (a valid
    // one from the issued SD-JWT) must break the binding.
    let issued = vector("rfc9901_5_1_issued.txt");
    let email = issued.split('~').nth(3).unwrap();
    let rfc = vector("rfc9901_5_2_presentation.txt");
    let (head, kb) = rfc.rsplit_once('~').unwrap();
    let presentation = format!("{head}~{email}~{kb}");
    assert_fails(
        &presentation,
        &rfc_issuer_key(),
        &rfc_kb_options(),
        ErrorKind::BindingMismatch("sd_hash"),
        Some(Position::KeyBinding),
    );
}

#[test]
fn duplicated_disclosure() {
    let rfc = vector("rfc9901_5_2_presentation.txt");
    let first = rfc.split('~').nth(1).unwrap();
    let presentation = rfc.replacen(first, &format!("{first}~{first}"), 1);
    assert_fails(
        &presentation,
        &rfc_issuer_key(),
        &rfc_kb_options(),
        ErrorKind::DuplicateDisclosure,
        Some(Position::Root),
    );
}

// --- Chain binding ---------------------------------------------------------

#[test]
fn swapped_closed_mandate_between_two_chains_with_the_same_agent_key() {
    // The draft's "Mandatory verification" attack: the user reuses one agent
    // key for two open mandates. A closed mandate made under mandate B must
    // not verify under mandate A.
    let parties = Parties::new();
    let a = parties.closed();
    let b = parties.closed();
    let (a_head, _) = a.rsplit_once("~~").unwrap();
    let (_, b_closed) = b.rsplit_once("~~").unwrap();
    assert_fails(
        &format!("{a_head}~~{b_closed}"),
        &parties.issuer.verifying_key(),
        &terminal_options(),
        ErrorKind::BindingMismatch("sd_hash"),
        Some(Position::Link(2)),
    );
}

#[test]
fn swapped_root_credential_with_the_same_user_key() {
    let parties = Parties::new();
    let presentation = parties.closed();
    let other_root = user_credential(&parties.issuer, &parties.user.verifying_key())
        .select(&["/vct"])
        .unwrap()
        .serialize();
    let (_, rest) = presentation.split_once("~~").unwrap();
    assert_fails(
        &format!("{other_root}~{rest}"),
        &parties.issuer.verifying_key(),
        &terminal_options(),
        ErrorKind::BindingMismatch("sd_hash"),
        Some(Position::Link(1)),
    );
}

#[test]
fn reordered_links() {
    let parties = Parties::new();
    let presentation = parties.closed();
    let parts: Vec<&str> = presentation.split("~~").collect();
    let reordered = format!(
        "{}~~{}~~{}~",
        parts[0],
        parts[2].trim_end_matches('~'),
        parts[1]
    );
    assert!(Unverified::<Presentation>::parse(&reordered).is_ok());
    let err = expect_err(
        &reordered,
        &parties.issuer.verifying_key(),
        &terminal_options(),
    );
    assert_eq!(err.position(), Some(Position::Link(1)));
}

#[test]
fn dropped_middle_link() {
    let parties = Parties::new();
    let presentation = parties.closed();
    let parts: Vec<&str> = presentation.split("~~").collect();
    let dropped = format!("{}~~{}", parts[0], parts[2]);
    // The closed mandate is signed by the agent, not the user the root names.
    let err = expect_err(
        &dropped,
        &parties.issuer.verifying_key(),
        &terminal_options(),
    );
    assert_eq!(err.position(), Some(Position::Link(1)));
}

#[test]
fn link_signed_by_a_key_other_than_the_previous_cnf() {
    let parties = Parties::new();
    let intruder = SigningKey::generate_p256();
    let presentation = Presentation::new(user_credential(
        &parties.issuer,
        &parties.user.verifying_key(),
    ))
    .delegate(
        LinkBuilder::new(open_mandate(&parties.agent.verifying_key())),
        &binding("a", "n", NOW),
        &intruder,
    )
    .unwrap()
    .bind(&binding(VERIFIER, CHALLENGE, NOW), &parties.agent)
    .unwrap()
    .serialize();
    assert_fails(
        &presentation,
        &parties.issuer.verifying_key(),
        &kb_options(),
        ErrorKind::BadSignature,
        Some(Position::Link(1)),
    );
}

#[test]
fn both_or_neither_binding_hash() {
    let parties = Parties::new();
    let root = user_credential(&parties.issuer, &parties.user.verifying_key()).serialize();
    let payload =
        json!({"vct": "x", "exp": NOW + 60, "cnf": parties.agent.verifying_key().to_cnf()});
    let mut both = envelope(&root, "a", "n");
    both["issuer_jwt_hash"] = json!("whatever");
    let mut neither = envelope(&root, "a", "n");
    neither.as_object_mut().unwrap().remove("sd_hash");
    for env in [both, neither] {
        let link = forge_link(typ::KB_SD_JWT_KB, env, payload.clone(), &parties.user);
        let options = VerifyOptions::new(NOW, typ::SD_JWT_VC, KeyBinding::NotRequired);
        assert_fails(
            &format!("{root}~{link}"),
            &parties.issuer.verifying_key(),
            &options,
            ErrorKind::AmbiguousBinding,
            Some(Position::Link(1)),
        );
    }
}

// --- typ per position ------------------------------------------------------

#[test]
fn wrong_root_typ() {
    let options = VerifyOptions::new(
        1_748_537_254,
        typ::SD_JWT_VC,
        KeyBinding::KbJwt {
            audience: "https://verifier.example.org".into(),
            nonce: "1234567890".into(),
        },
    );
    let err = expect_err(
        &vector("rfc9901_5_2_presentation.txt"),
        &rfc_issuer_key(),
        &options,
    );
    assert!(
        matches!(err.kind(), ErrorKind::WrongTyp { found: Some(t), .. } if t == "example+sd-jwt")
    );
    assert_eq!(err.position(), Some(Position::Root));
}

#[test]
fn kb_jwt_with_a_plain_jwt_typ() {
    let parties = Parties::new();
    let root = user_credential(&parties.issuer, &parties.user.verifying_key()).serialize();
    let kb = forge(
        json!({"alg": "ES256", "typ": "JWT"}),
        json!({"iat": NOW, "aud": VERIFIER, "nonce": CHALLENGE, "sd_hash": aap_sdjwt::SdAlg::Sha256.digest(&root)}),
        &parties.user,
    );
    let err = expect_err(
        &format!("{root}{kb}"),
        &parties.issuer.verifying_key(),
        &kb_options(),
    );
    assert!(matches!(err.kind(), ErrorKind::WrongTyp { .. }));
    assert_eq!(err.position(), Some(Position::KeyBinding));
}

#[test]
fn terminal_typ_on_a_link_that_is_followed_by_another() {
    let parties = Parties::new();
    let root = user_credential(&parties.issuer, &parties.user.verifying_key()).serialize();
    let link = forge_link(
        typ::KB_SD_JWT,
        envelope(&root, "a", "n"),
        json!({"vct": "x", "exp": NOW + 60, "cnf": parties.agent.verifying_key().to_cnf()}),
        &parties.user,
    );
    let presentation = Unverified::<Presentation>::parse(&format!("{root}~{link}"))
        .unwrap()
        .into_inner()
        .bind(&binding(VERIFIER, CHALLENGE, NOW), &parties.agent)
        .unwrap()
        .serialize();
    let err = expect_err(
        &presentation,
        &parties.issuer.verifying_key(),
        &kb_options(),
    );
    assert!(matches!(err.kind(), ErrorKind::WrongTyp { .. }));
    assert_eq!(err.position(), Some(Position::Link(1)));
}

#[test]
fn delegating_typ_where_a_closed_mandate_is_required() {
    let parties = Parties::new();
    let presentation = parties.delegated().serialize();
    let err = expect_err(
        &presentation,
        &parties.issuer.verifying_key(),
        &terminal_options(),
    );
    assert!(matches!(err.kind(), ErrorKind::WrongTyp { .. }));
    assert_eq!(err.position(), Some(Position::Link(1)));
}

#[test]
fn cnf_must_match_the_link_typ() {
    let parties = Parties::new();
    let root = user_credential(&parties.issuer, &parties.user.verifying_key()).serialize();
    let options = VerifyOptions::new(NOW, typ::SD_JWT_VC, KeyBinding::NotRequired);

    let no_cnf = forge_link(
        typ::KB_SD_JWT_KB,
        envelope(&root, "a", "n"),
        json!({"vct": "x", "exp": NOW + 60}),
        &parties.user,
    );
    assert_fails(
        &format!("{root}~{no_cnf}"),
        &parties.issuer.verifying_key(),
        &options,
        ErrorKind::MissingCnf,
        Some(Position::Link(1)),
    );

    let terminal_with_cnf = forge_link(
        typ::KB_SD_JWT,
        envelope(&root, VERIFIER, CHALLENGE),
        json!({"vct": "x", "cnf": parties.agent.verifying_key().to_cnf()}),
        &parties.user,
    );
    assert_fails(
        &format!("{root}~{terminal_with_cnf}"),
        &parties.issuer.verifying_key(),
        &terminal_options(),
        ErrorKind::UnexpectedCnf,
        Some(Position::Link(1)),
    );
}

// --- alg -------------------------------------------------------------------

#[test]
fn alg_header_lies_about_the_key() {
    let parties = Parties::new();
    let root = user_credential(&parties.issuer, &parties.user.verifying_key()).serialize();
    let mut env = envelope(&root, "a", "n").as_object().unwrap().clone();
    let (disclosure, digest) = payload_disclosure(
        json!({"vct": "x", "exp": NOW + 60, "cnf": parties.agent.verifying_key().to_cnf()}),
    );
    env.insert("delegate_payload".into(), json!([{ "...": digest }]));
    let options = VerifyOptions::new(NOW, typ::SD_JWT_VC, KeyBinding::NotRequired);
    // The user key is P-256; these headers claim otherwise.
    for alg in [json!("EdDSA"), json!("none"), json!("HS256"), json!(null)] {
        let jwt = forge(
            json!({"alg": alg, "typ": typ::KB_SD_JWT_KB}),
            serde_json::Value::Object(env.clone()),
            &parties.user,
        );
        let err = expect_err(
            &format!("{root}~{jwt}~{disclosure}~"),
            &parties.issuer.verifying_key(),
            &options,
        );
        assert!(
            matches!(
                err.kind(),
                ErrorKind::AlgorithmMismatch {
                    expected: "ES256",
                    ..
                }
            ),
            "{alg}: {err}"
        );
        assert_eq!(err.position(), Some(Position::Link(1)));
    }
}

#[test]
fn issuer_key_of_the_other_algorithm() {
    let ed_issuer = SigningKey::generate_ed25519();
    let err = expect_err(
        &vector("rfc9901_5_2_presentation.txt"),
        &ed_issuer.verifying_key(),
        &rfc_kb_options(),
    );
    assert!(matches!(
        err.kind(),
        ErrorKind::AlgorithmMismatch {
            expected: "EdDSA",
            ..
        }
    ));
    assert_eq!(err.position(), Some(Position::Root));
}

#[test]
fn right_algorithm_wrong_issuer_key() {
    let err = expect_err(
        &vector("rfc9901_5_2_presentation.txt"),
        &SigningKey::generate_p256().verifying_key(),
        &rfc_kb_options(),
    );
    assert_eq!(err.kind(), &ErrorKind::BadSignature);
}

// --- Key binding presence is the verifier's decision ------------------------

#[test]
fn missing_key_binding() {
    // RFC 5.2 with its KB-JWT cut off.
    let rfc = vector("rfc9901_5_2_presentation.txt");
    let (head, _) = rfc.rsplit_once('~').unwrap();
    assert_fails(
        &format!("{head}~"),
        &rfc_issuer_key(),
        &rfc_kb_options(),
        ErrorKind::MissingKeyBinding,
        Some(Position::KeyBinding),
    );

    // A root alone where a closed mandate is required.
    let parties = Parties::new();
    let root = user_credential(&parties.issuer, &parties.user.verifying_key()).serialize();
    assert_fails(
        &root,
        &parties.issuer.verifying_key(),
        &terminal_options(),
        ErrorKind::MissingKeyBinding,
        Some(Position::Root),
    );
}

#[test]
fn unexpected_key_binding() {
    let options = VerifyOptions::new(1_748_537_254, "example+sd-jwt", KeyBinding::NotRequired);
    assert_fails(
        &vector("rfc9901_5_2_presentation.txt"),
        &rfc_issuer_key(),
        &options,
        ErrorKind::UnexpectedKeyBinding,
        Some(Position::KeyBinding),
    );
}

#[test]
fn kb_jwt_signed_by_someone_other_than_the_holder() {
    let parties = Parties::new();
    let presentation = Presentation::new(user_credential(
        &parties.issuer,
        &parties.user.verifying_key(),
    ))
    .bind(&binding(VERIFIER, CHALLENGE, NOW), &parties.agent)
    .unwrap()
    .serialize();
    assert_fails(
        &presentation,
        &parties.issuer.verifying_key(),
        &kb_options(),
        ErrorKind::BadSignature,
        Some(Position::KeyBinding),
    );
}

// --- Freshness and transaction binding -------------------------------------

#[test]
fn kb_jwt_audience_nonce_and_iat_window() {
    let rfc = vector("rfc9901_5_2_presentation.txt");
    let key = rfc_issuer_key();
    let with = |aud: &str, nonce: &str, now: i64| {
        VerifyOptions::new(
            now,
            "example+sd-jwt",
            KeyBinding::KbJwt {
                audience: aud.into(),
                nonce: nonce.into(),
            },
        )
    };
    let iat = 1_748_537_244;
    let aud = "https://verifier.example.org";
    let at = Some(Position::KeyBinding);
    assert_fails(
        &rfc,
        &key,
        &with("https://evil.example", "1234567890", iat),
        ErrorKind::AudienceMismatch,
        at,
    );
    assert_fails(
        &rfc,
        &key,
        &with(aud, "replayed", iat),
        ErrorKind::NonceMismatch,
        at,
    );
    assert_fails(
        &rfc,
        &key,
        &with(aud, "1234567890", iat + 301),
        ErrorKind::IatOutOfWindow,
        at,
    );
    assert_fails(
        &rfc,
        &key,
        &with(aud, "1234567890", iat - 31),
        ErrorKind::IatOutOfWindow,
        at,
    );
    assert!(verify(&rfc, &key, &with(aud, "1234567890", iat + 300)).is_ok());
    assert!(verify(&rfc, &key, &with(aud, "1234567890", iat - 30)).is_ok());
}

#[test]
fn closed_mandate_audience_nonce_and_iat_window() {
    let parties = Parties::new();
    let presentation = parties.closed();
    let key = parties.issuer.verifying_key();
    let with = |aud: &str, nonce: &str, now: i64| {
        let mut o = terminal_options();
        o.now = now;
        o.key_binding = KeyBinding::TerminalLink {
            audience: aud.into(),
            nonce: nonce.into(),
        };
        o
    };
    let at = Some(Position::Link(2));
    assert_fails(
        &presentation,
        &key,
        &with("https://evil.example", CHALLENGE, NOW),
        ErrorKind::AudienceMismatch,
        at,
    );
    assert_fails(
        &presentation,
        &key,
        &with(VERIFIER, "other", NOW),
        ErrorKind::NonceMismatch,
        at,
    );
    assert_fails(
        &presentation,
        &key,
        &with(VERIFIER, CHALLENGE, NOW + 301),
        ErrorKind::IatOutOfWindow,
        at,
    );
}

#[test]
fn expired_and_not_yet_valid_links() {
    let parties = Parties::new();
    let presentation = parties.closed();
    let key = parties.issuer.verifying_key();
    // The open mandate expires at NOW + 3600; the root much later.
    let mut late = terminal_options();
    late.now = NOW + 3600;
    late.max_age = i64::MAX / 2;
    assert_fails(
        &presentation,
        &key,
        &late,
        ErrorKind::Expired,
        Some(Position::Link(1)),
    );
    late.leeway = 1;
    assert!(verify(&presentation, &key, &late).is_ok());

    let root = SdJwtBuilderFor::root(&parties, json!({"nbf": NOW + 10, "exp": NOW + 20}));
    let options = VerifyOptions::new(NOW, typ::SD_JWT_VC, KeyBinding::NotRequired);
    assert_fails(
        &root,
        &key,
        &options,
        ErrorKind::NotYetValid,
        Some(Position::Root),
    );

    let root = SdJwtBuilderFor::root(&parties, json!({"exp": NOW}));
    assert_fails(
        &root,
        &key,
        &options,
        ErrorKind::Expired,
        Some(Position::Root),
    );

    let root = SdJwtBuilderFor::root(&parties, json!({"exp": "tomorrow"}));
    assert_fails(
        &root,
        &key,
        &options,
        ErrorKind::InvalidClaim("exp"),
        Some(Position::Root),
    );
}

#[test]
fn exp_is_required_on_delegating_elements_but_can_hide_behind_a_disclosure() {
    let parties = Parties::new();
    let key = parties.issuer.verifying_key();
    let options = VerifyOptions::new(NOW, typ::SD_JWT_VC, KeyBinding::NotRequired);

    let no_exp = SdJwtBuilderFor::root(&parties, json!({}));
    assert_fails(
        &no_exp,
        &key,
        &options,
        ErrorKind::MissingExp,
        Some(Position::Root),
    );

    // A selectively disclosable exp the holder leaves out is a missing exp
    // (RFC 9901 §9.7), not a credential without expiry.
    let hidden = aap_sdjwt::SdJwtBuilder::new(
        typ::SD_JWT_VC,
        obj(json!({"exp": NOW + 60, "cnf": parties.user.verifying_key().to_cnf()})),
    )
    .conceal("/exp")
    .sign(&parties.issuer)
    .unwrap();
    let withheld = hidden.select(&["/cnf"]).unwrap().serialize();
    assert_fails(
        &withheld,
        &key,
        &options,
        ErrorKind::MissingExp,
        Some(Position::Root),
    );
    assert!(verify(&hidden.serialize(), &key, &options).is_ok());

    let root = user_credential(&parties.issuer, &parties.user.verifying_key()).serialize();
    let link = forge_link(
        typ::KB_SD_JWT_KB,
        envelope(&root, "a", "n"),
        json!({"vct": "x", "cnf": parties.agent.verifying_key().to_cnf()}),
        &parties.user,
    );
    assert_fails(
        &format!("{root}~{link}"),
        &key,
        &options,
        ErrorKind::MissingExp,
        Some(Position::Link(1)),
    );
}

/// Root credentials with arbitrary validity claims.
struct SdJwtBuilderFor;

impl SdJwtBuilderFor {
    fn root(parties: &Parties, validity: serde_json::Value) -> String {
        let mut claims = obj(json!({"iss": "https://issuer.aap.example"}));
        claims.extend(obj(validity));
        aap_sdjwt::SdJwtBuilder::new(typ::SD_JWT_VC, claims)
            .sign(&parties.issuer)
            .unwrap()
            .serialize()
    }
}

// --- Delegate payload shape -------------------------------------------------

#[test]
fn several_inline_delegate_payloads_are_rejected() {
    let parties = Parties::new();
    let root = user_credential(&parties.issuer, &parties.user.verifying_key()).serialize();
    let mut env = envelope(&root, "a", "n");
    env["delegate_payload"] = json!([{"vct": "a"}, {"vct": "b"}]);
    let link = forge(
        json!({"alg": "ES256", "typ": typ::KB_SD_JWT}),
        env,
        &parties.user,
    );
    let options = VerifyOptions::new(NOW, typ::SD_JWT_VC, KeyBinding::NotRequired);
    assert_fails(
        &format!("{root}~{link}~"),
        &parties.issuer.verifying_key(),
        &options,
        ErrorKind::DelegatePayload("with several elements, each must be a disclosure digest"),
        Some(Position::Link(1)),
    );
}

#[test]
fn undisclosed_delegate_payload_is_rejected() {
    let parties = Parties::new();
    let presentation = parties.delegated();
    let (root, link) = presentation
        .serialize()
        .split_once("~~")
        .map(|(a, b)| (a.to_owned(), b.to_owned()))
        .unwrap();
    let link_jwt = link.split('~').next().unwrap();
    let options = VerifyOptions::new(NOW, typ::SD_JWT_VC, KeyBinding::NotRequired);
    assert_fails(
        &format!("{root}~~{link_jwt}~"),
        &parties.issuer.verifying_key(),
        &options,
        ErrorKind::DelegatePayload("exactly one element must be disclosed"),
        Some(Position::Link(1)),
    );
}

#[test]
fn sd_alg_inside_a_delegate_payload_is_rejected() {
    let parties = Parties::new();
    let root = user_credential(&parties.issuer, &parties.user.verifying_key()).serialize();
    let link = forge_link(
        typ::KB_SD_JWT_KB,
        envelope(&root, "a", "n"),
        json!({"_sd_alg": "sha-512", "exp": NOW + 60, "cnf": parties.agent.verifying_key().to_cnf()}),
        &parties.user,
    );
    let options = VerifyOptions::new(NOW, typ::SD_JWT_VC, KeyBinding::NotRequired);
    assert_fails(
        &format!("{root}~{link}"),
        &parties.issuer.verifying_key(),
        &options,
        ErrorKind::ReservedName("_sd_alg".into()),
        Some(Position::Link(1)),
    );
}

// --- Serialization and limits ---------------------------------------------

#[test]
fn malformed_serializations() {
    let parties = Parties::new();
    let presentation = parties.closed();
    for broken in [
        presentation.replacen("~~", "~~~", 1),
        presentation.trim_end_matches('~').to_owned(),
        presentation.replacen("~~", "~", 1),
        format!("~{presentation}"),
    ] {
        let err = expect_err(
            &broken,
            &parties.issuer.verifying_key(),
            &terminal_options(),
        );
        assert!(
            matches!(
                err.kind(),
                ErrorKind::Malformed(_) | ErrorKind::Base64 | ErrorKind::Json(_)
            ),
            "{broken}: {err}"
        );
    }
}

#[test]
fn chain_length_is_bounded() {
    let parties = Parties::new();
    let mut options = terminal_options();
    options.max_links = 1;
    let err = expect_err(&parties.closed(), &parties.issuer.verifying_key(), &options);
    assert_eq!(
        err.kind(),
        &ErrorKind::Malformed("more links than max_links")
    );
}

#[test]
fn unsupported_sd_alg_and_crit_header_in_the_root() {
    let parties = Parties::new();
    let key = parties.issuer.verifying_key();
    let options = VerifyOptions::new(NOW, typ::SD_JWT_VC, KeyBinding::NotRequired);
    let md5 = forge(
        json!({"alg": "ES256", "typ": typ::SD_JWT_VC}),
        json!({"_sd_alg": "md5", "exp": NOW + 60}),
        &parties.issuer,
    );
    assert_fails(
        &format!("{md5}~"),
        &key,
        &options,
        ErrorKind::UnsupportedSdAlg("md5".into()),
        Some(Position::Root),
    );
    let crit = forge(
        json!({"alg": "ES256", "typ": typ::SD_JWT_VC, "crit": ["x"], "x": 1}),
        json!({"exp": NOW + 60}),
        &parties.issuer,
    );
    assert_fails(
        &format!("{crit}~"),
        &key,
        &options,
        ErrorKind::UnsupportedHeader("crit".into()),
        Some(Position::Root),
    );
}
