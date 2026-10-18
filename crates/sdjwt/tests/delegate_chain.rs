//! Delegate SD-JWT chains (draft-gco-oauth-delegate-sd-jwt). The draft has
//! no example tokens, so these build chains with this crate and check every
//! shape the draft defines, plus the AP2 closed-mandate form.

mod common;

use aap_sdjwt::{
    typ, HashBinding, KeyBinding, LinkBuilder, LinkKind, Presentation, SdPayload, SigningKey,
    Unverified, VerifyOptions,
};
use common::*;
use serde_json::{json, Value};

#[test]
fn closed_mandate_chain_user_to_agent_to_merchant() {
    let parties = Parties::new();
    let chain = verify(
        &parties.closed(),
        &parties.issuer.verifying_key(),
        &terminal_options(),
    )
    .unwrap();

    let root = chain.root();
    assert_eq!(root.kind(), LinkKind::Root);
    assert_eq!(root.claims()["vct"], "urn:aap:user:1");
    assert!(root.claims().get("given_name").is_none(), "not disclosed");
    assert_eq!(root.cnf(), Some(&parties.user.verifying_key()));

    let [open, closed] = chain.delegations() else {
        panic!("expected two links");
    };
    assert_eq!(open.kind(), LinkKind::Delegation);
    assert_eq!(open.header()["typ"], typ::KB_SD_JWT_KB);
    assert_eq!(open.claims()["vct"], "mandate.checkout.open.1");
    assert_eq!(open.cnf(), Some(&parties.agent.verifying_key()));
    // Only merchant_1 was disclosed to the merchant.
    assert_eq!(
        open.claims()["constraints"][0]["allowed"],
        json!([{"id": "merchant_1", "website": "https://merchant.example"}])
    );
    assert_eq!(open.envelope()["aud"], "https://agent.example");

    assert_eq!(closed.kind(), LinkKind::Terminal);
    assert_eq!(closed.header()["typ"], typ::KB_SD_JWT);
    assert_eq!(closed.claims()["vct"], "mandate.checkout.1");
    assert_eq!(closed.envelope()["aud"], VERIFIER);
    assert_eq!(closed.envelope()["nonce"], CHALLENGE);
    assert!(closed.cnf().is_none());
    assert_eq!(chain.leaf().position(), closed.position());
    assert!(chain.key_binding().is_none());

    // Each link's sd_hash commits to the previous element as presented.
    for pair in chain.links().windows(2) {
        let (prev, next) = (&pair[0], &pair[1]);
        assert_eq!(
            next.envelope()["sd_hash"],
            prev.sd_alg().digest(prev.sd_jwt())
        );
    }
}

#[test]
fn dsd_jwt_plus_kb_ends_in_a_kb_jwt_from_the_delegate() {
    let parties = Parties::new();
    let presentation = parties
        .delegated()
        .select(1, &["/delegate_payload/0/constraints/1"])
        .unwrap()
        .bind(&binding(VERIFIER, CHALLENGE, NOW), &parties.agent)
        .unwrap()
        .serialize();
    let chain = verify(
        &presentation,
        &parties.issuer.verifying_key(),
        &kb_options(),
    )
    .unwrap();
    assert_eq!(chain.delegations().len(), 1);
    assert_eq!(chain.leaf().kind(), LinkKind::Delegation);
    let open = &chain.delegations()[0];
    assert_eq!(open.claims()["constraints"][0]["allowed"], json!([]));
    assert_eq!(open.claims()["constraints"][1]["max"], 15000);
    let kb = chain.key_binding().unwrap();
    assert_eq!(kb.header()["typ"], typ::KB_JWT);
    assert_eq!(kb.claims()["aud"], VERIFIER);
}

#[test]
fn sub_delegation_from_agent_to_sub_agent() {
    let parties = Parties::new();
    let sub_agent = SigningKey::generate_ed25519();
    let sub_mandate = SdPayload::new(obj(json!({
        "vct": "mandate.checkout.open.1",
        "exp": NOW + 600,
        "cnf": sub_agent.verifying_key().to_cnf(),
        "constraints": [{"type": "payment.amount_range", "max": 5000, "currency": "USD"}]
    })));
    let presentation = parties
        .delegated()
        .select(1, &["/delegate_payload/0/constraints/0/allowed/0"])
        .unwrap()
        .delegate(
            LinkBuilder::new(sub_mandate),
            &binding("https://sub-agent.example", "sub-nonce", NOW - 30),
            &parties.agent,
        )
        .unwrap()
        .delegate(
            LinkBuilder::new(closed_mandate()),
            &binding(VERIFIER, CHALLENGE, NOW),
            &sub_agent,
        )
        .unwrap()
        .serialize();
    let chain = verify(
        &presentation,
        &parties.issuer.verifying_key(),
        &terminal_options(),
    )
    .unwrap();
    let kinds: Vec<LinkKind> = chain.links().iter().map(|l| l.kind()).collect();
    assert_eq!(
        kinds,
        [
            LinkKind::Root,
            LinkKind::Delegation,
            LinkKind::Delegation,
            LinkKind::Terminal
        ]
    );
    assert_eq!(chain.links()[2].cnf(), Some(&sub_agent.verifying_key()));
    assert_eq!(chain.links()[2].claims()["constraints"][0]["max"], 5000);
}

#[test]
fn issuer_jwt_hash_lets_a_later_holder_drop_earlier_disclosures() {
    let parties = Parties::new();
    let root = user_credential(&parties.issuer, &parties.user.verifying_key());
    let delegate = |binding_mode| {
        Presentation::new(root.clone())
            .delegate(
                LinkBuilder::new(open_mandate(&parties.agent.verifying_key()))
                    .binding(binding_mode),
                &binding("https://agent.example", "n", NOW),
                &parties.user,
            )
            .unwrap()
    };

    // The user delegated with every root disclosure attached (names
    // included); the agent strips them before presenting.
    for (mode, expect_ok) in [
        (HashBinding::IssuerJwtHash, true),
        (HashBinding::SdHash, false),
    ] {
        let presentation = delegate(mode)
            .select(0, &["/vct"])
            .unwrap()
            .bind(&binding(VERIFIER, CHALLENGE, NOW), &parties.agent)
            .unwrap()
            .serialize();
        let result = verify(
            &presentation,
            &parties.issuer.verifying_key(),
            &kb_options(),
        );
        match (expect_ok, result) {
            (true, Ok(chain)) => {
                assert!(chain.root().claims().get("given_name").is_none());
                assert!(chain.delegations()[0]
                    .envelope()
                    .contains_key("issuer_jwt_hash"));
            }
            (false, Err(e)) => {
                assert_eq!(e.kind(), &aap_sdjwt::ErrorKind::BindingMismatch("sd_hash"));
                assert_eq!(e.position(), Some(aap_sdjwt::Position::Link(1)));
            }
            (_, other) => panic!("{mode:?}: {other:?}"),
        }
    }
}

#[test]
fn mixed_algorithms_along_the_chain() {
    let issuer = SigningKey::generate_ed25519();
    let user = SigningKey::generate_p256();
    let agent = SigningKey::generate_ed25519();
    let presentation = Presentation::new(user_credential(&issuer, &user.verifying_key()))
        .delegate(
            LinkBuilder::new(open_mandate(&agent.verifying_key())),
            &binding("https://agent.example", "n", NOW),
            &user,
        )
        .unwrap()
        .delegate(
            LinkBuilder::new(closed_mandate()),
            &binding(VERIFIER, CHALLENGE, NOW),
            &agent,
        )
        .unwrap()
        .serialize();
    let chain = verify(&presentation, &issuer.verifying_key(), &terminal_options()).unwrap();
    assert_eq!(chain.root().header()["alg"], "EdDSA");
    assert_eq!(chain.delegations()[0].header()["alg"], "ES256");
    assert_eq!(chain.delegations()[1].header()["alg"], "EdDSA");
}

#[test]
fn one_signature_several_delegate_payloads_exactly_one_presented() {
    let parties = Parties::new();
    let agent = parties.agent.verifying_key();
    let second = SdPayload::new(obj(json!({
        "vct": "mandate.payment.open.1",
        "exp": NOW + 3600,
        "cnf": agent.to_cnf(),
        "constraints": [{"type": "payment.amount_range", "max": 15000, "currency": "USD"}]
    })));
    let delegated = Presentation::new(user_credential(
        &parties.issuer,
        &parties.user.verifying_key(),
    ))
    .delegate(
        LinkBuilder::new(open_mandate(&agent)).add_payload(second),
        &binding("https://agent.example", "n", NOW),
        &parties.user,
    )
    .unwrap();
    assert_eq!(
        delegated.links()[0].unverified_payload()["delegate_payload"]
            .as_array()
            .unwrap()
            .len(),
        2
    );

    for index in 0..2 {
        let presentation = delegated
            .clone()
            .select(1, &[&format!("/delegate_payload/{index}")])
            .unwrap()
            .bind(&binding(VERIFIER, CHALLENGE, NOW), &parties.agent)
            .unwrap()
            .serialize();
        let chain = verify(
            &presentation,
            &parties.issuer.verifying_key(),
            &kb_options(),
        )
        .unwrap();
        let vct = chain.delegations()[0].claims()["vct"]
            .as_str()
            .unwrap()
            .to_owned();
        assert!(vct.starts_with("mandate."), "{vct}");
    }

    // Disclosing both breaks "exactly one disclosed element".
    let both = delegated
        .bind(&binding(VERIFIER, CHALLENGE, NOW), &parties.agent)
        .unwrap()
        .serialize();
    let err = verify(&both, &parties.issuer.verifying_key(), &kb_options()).unwrap_err();
    assert_eq!(
        err.kind(),
        &aap_sdjwt::ErrorKind::DelegatePayload("exactly one element must be disclosed")
    );
}

#[test]
fn link_payloads_must_agree_on_cnf() {
    let parties = Parties::new();
    let mixed = LinkBuilder::new(open_mandate(&parties.agent.verifying_key()))
        .add_payload(closed_mandate());
    let err = Presentation::new(user_credential(
        &parties.issuer,
        &parties.user.verifying_key(),
    ))
    .delegate(mixed, &binding("a", "n", NOW), &parties.user)
    .unwrap_err();
    assert!(matches!(err.kind(), aap_sdjwt::ErrorKind::Issuance(_)));
}

#[test]
fn dsd_jwt_without_key_binding_when_the_verifier_does_not_require_it() {
    let parties = Parties::new();
    let presentation = parties.delegated().serialize();
    let options = VerifyOptions::new(NOW, typ::SD_JWT_VC, KeyBinding::NotRequired);
    let chain = verify(&presentation, &parties.issuer.verifying_key(), &options).unwrap();
    assert_eq!(chain.leaf().kind(), LinkKind::Delegation);
}

#[test]
fn draft_00_typ_spelling_is_accepted_for_delegating_links() {
    // AP2's reference SDK still emits draft-00's "kb+sd-jwt+kb".
    let parties = Parties::new();
    let root = user_credential(&parties.issuer, &parties.user.verifying_key()).serialize();
    let link = forge_link(
        typ::KB_SD_JWT_KB_DRAFT_00,
        envelope(&root, "https://agent.example", "n"),
        json!({"vct": "mandate.checkout.open.1", "exp": NOW + 60, "cnf": parties.agent.verifying_key().to_cnf()}),
        &parties.user,
    );
    let presentation = Unverified::<Presentation>::parse(&format!("{root}~{link}"))
        .unwrap()
        .into_inner()
        .bind(&binding(VERIFIER, CHALLENGE, NOW), &parties.agent)
        .unwrap()
        .serialize();
    let chain = verify(
        &presentation,
        &parties.issuer.verifying_key(),
        &kb_options(),
    )
    .unwrap();
    assert_eq!(chain.leaf().kind(), LinkKind::Delegation);
}

#[test]
fn verified_chain_keeps_the_presentation_verbatim() {
    let parties = Parties::new();
    let presentation = parties.closed();
    let chain = verify(
        &presentation,
        &parties.issuer.verifying_key(),
        &terminal_options(),
    )
    .unwrap();
    assert_eq!(chain.serialized(), presentation);
    let rebuilt: String = chain
        .links()
        .iter()
        .map(|l| l.sd_jwt())
        .collect::<Vec<_>>()
        .join("~");
    assert_eq!(rebuilt, presentation);
    let _: &Value = &chain.leaf().claims()["amount"]["value"];
}
