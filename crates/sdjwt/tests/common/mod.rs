//! Shared fixtures for the integration tests. Each test binary uses a
//! different subset, hence the `dead_code` allowance.
#![allow(dead_code)]

use aap_sdjwt::{
    BindingClaims, KeyBinding, LinkBuilder, Presentation, SdJwt, SdJwtBuilder, SdPayload, Signer,
    SigningKey, Unverified, VerifiedChain, VerifyOptions, VerifyingKey,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine as _};
use serde_json::{json, Map, Value};

pub const NOW: i64 = 1_800_000_000;
pub const VERIFIER: &str = "https://merchant.example";
pub const CHALLENGE: &str = "n-0S6_WzA2Mj";

pub fn vector(name: &str) -> String {
    let path = format!("{}/tests/vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{path}: {e}"))
        .trim()
        .to_owned()
}

pub fn vector_json(name: &str) -> Value {
    serde_json::from_str(&vector(name)).unwrap()
}

/// RFC 9901 Appendix A.5: the key behind every Issuer signature in the
/// RFC's examples.
pub fn rfc_issuer_key() -> VerifyingKey {
    VerifyingKey::from_jwk(&json!({
        "kty": "EC",
        "crv": "P-256",
        "x": "b28d4MwZMjw8-00CG4xfnn9SLMVMM19SlqZpVb_uNtQ",
        "y": "Xv5zWwuoaTgdS6hV43yI6gBwTnjukmFQQnJ_kCxzqk8"
    }))
    .unwrap()
}

pub fn obj(v: Value) -> Map<String, Value> {
    match v {
        Value::Object(o) => o,
        other => panic!("not an object: {other}"),
    }
}

pub fn binding(audience: &str, nonce: &str, issued_at: i64) -> BindingClaims {
    BindingClaims {
        audience: audience.into(),
        nonce: nonce.into(),
        issued_at,
    }
}

/// An AL0-style user credential: SD-JWT VC from `issuer`, bound to `user`.
pub fn user_credential(issuer: &SigningKey, user: &VerifyingKey) -> SdJwt {
    SdJwtBuilder::new(
        aap_sdjwt::typ::SD_JWT_VC,
        obj(json!({
            "iss": "https://issuer.aap.example",
            "vct": "urn:aap:user:1",
            "iat": NOW - 86_400,
            "exp": NOW + 86_400 * 365,
            "given_name": "Ada",
            "family_name": "Lovelace",
            "cnf": user.to_cnf(),
        })),
    )
    .conceal("/given_name")
    .conceal("/family_name")
    .decoys("", 2)
    .sign(issuer)
    .unwrap()
}

/// An open mandate in AP2's shape: constraints whose allowed values are
/// individually disclosable, bound to `agent`.
pub fn open_mandate(agent: &VerifyingKey) -> SdPayload {
    SdPayload::new(obj(json!({
        "vct": "mandate.checkout.open.1",
        "iat": NOW - 60,
        "exp": NOW + 3600,
        "cnf": agent.to_cnf(),
        "constraints": [
            {
                "type": "checkout.allowed_merchants",
                "allowed": [
                    {"id": "merchant_1", "website": "https://merchant.example"},
                    {"id": "merchant_2", "website": "https://other.example"},
                    {"id": "merchant_3", "website": "https://third.example"}
                ]
            },
            {"type": "payment.amount_range", "max": 15000, "currency": "USD"}
        ]
    })))
    .conceal("/constraints/0/allowed/0")
    .conceal("/constraints/0/allowed/1")
    .conceal("/constraints/0/allowed/2")
}

/// A closed mandate: the concrete action, no `cnf`.
pub fn closed_mandate() -> SdPayload {
    SdPayload::new(obj(json!({
        "vct": "mandate.checkout.1",
        "checkout_hash": "3WiKMabE8NRYJgveUbyAZ3pBqRfPrWwGDbOyvbO1eYA",
        "payee": {"id": "merchant_1"},
        "amount": {"value": 12000, "currency": "USD"}
    })))
}

pub struct Parties {
    pub issuer: SigningKey,
    pub user: SigningKey,
    pub agent: SigningKey,
}

impl Parties {
    pub fn new() -> Self {
        Parties {
            issuer: SigningKey::generate_p256(),
            user: SigningKey::generate_p256(),
            agent: SigningKey::generate_p256(),
        }
    }

    /// root ~~ open mandate (user -> agent), agent's view: everything.
    pub fn delegated(&self) -> Presentation {
        let root = user_credential(&self.issuer, &self.user.verifying_key());
        Presentation::new(root)
            .select(0, &["/vct"])
            .unwrap()
            .delegate(
                LinkBuilder::new(open_mandate(&self.agent.verifying_key())),
                &binding("https://agent.example", "agent-nonce", NOW - 60),
                &self.user,
            )
            .unwrap()
    }

    /// root ~~ open mandate ~~ closed mandate for merchant_1, as the agent
    /// presents it to the merchant.
    pub fn closed(&self) -> String {
        self.delegated()
            .select(1, &["/delegate_payload/0/constraints/0/allowed/0"])
            .unwrap()
            .delegate(
                LinkBuilder::new(closed_mandate()),
                &binding(VERIFIER, CHALLENGE, NOW),
                &self.agent,
            )
            .unwrap()
            .serialize()
    }
}

pub fn terminal_options() -> VerifyOptions {
    VerifyOptions::new(
        NOW,
        aap_sdjwt::typ::SD_JWT_VC,
        KeyBinding::TerminalLink {
            audience: VERIFIER.into(),
            nonce: CHALLENGE.into(),
        },
    )
}

pub fn kb_options() -> VerifyOptions {
    VerifyOptions::new(
        NOW,
        aap_sdjwt::typ::SD_JWT_VC,
        KeyBinding::KbJwt {
            audience: VERIFIER.into(),
            nonce: CHALLENGE.into(),
        },
    )
}

pub fn verify(
    presentation: &str,
    issuer: &VerifyingKey,
    options: &VerifyOptions,
) -> Result<VerifiedChain, aap_sdjwt::Error> {
    Unverified::<Presentation>::parse(presentation)?.verify(issuer, options)
}

/// Signs arbitrary header and payload JSON, the way an attacker (or a
/// non-conforming implementation) would. `alg` is taken from `header` as
/// given, so it can lie about the key.
pub fn forge(header: Value, payload: Value, key: &SigningKey) -> String {
    let input = format!(
        "{}.{}",
        B64.encode(header.to_string()),
        B64.encode(payload.to_string())
    );
    let sig = key.sign(input.as_bytes()).unwrap();
    format!("{input}.{}", B64.encode(sig))
}

/// An array-element disclosure wrapping a Delegate Payload, and its digest.
pub fn payload_disclosure(payload: Value) -> (String, String) {
    let disclosure = B64.encode(json!(["c2FsdHNhbHRzYWx0c2FsdA", payload]).to_string());
    let digest = aap_sdjwt::SdAlg::Sha256.digest(&disclosure);
    (disclosure, digest)
}

/// A hand-made KB-SD-JWT after `previous` (an element in its `<JWT>~...~`
/// form): `typ` and `envelope` exactly as given, one Delegate Payload
/// disclosed, signed by `key`. Returns the link in its `<JWT>~<D>~` form.
pub fn forge_link(typ: &str, envelope: Value, delegate_payload: Value, key: &SigningKey) -> String {
    let (disclosure, digest) = payload_disclosure(delegate_payload);
    let mut payload = obj(envelope);
    payload
        .entry("delegate_payload")
        .or_insert_with(|| json!([{ "...": digest }]));
    let alg = key.verifying_key().algorithm().as_str();
    let jwt = forge(json!({"alg": alg, "typ": typ}), Value::Object(payload), key);
    format!("{jwt}~{disclosure}~")
}

/// The standard envelope of a KB-SD-JWT bound to `previous` by `sd_hash`.
pub fn envelope(previous: &str, audience: &str, nonce: &str) -> Value {
    json!({
        "iat": NOW,
        "aud": audience,
        "nonce": nonce,
        "sd_hash": aap_sdjwt::SdAlg::Sha256.digest(previous),
    })
}

pub fn b64_json(segment: &str) -> Value {
    serde_json::from_slice(&B64.decode(segment).unwrap()).unwrap()
}

pub fn b64(data: &str) -> String {
    B64.encode(data)
}
