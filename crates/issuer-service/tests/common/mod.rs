//! Test kit: a synthetic Apple-style PKI plus builders for attestations,
//! assertions and proof-of-possession JWSs, so every verification path can be
//! exercised without any device capture. Nothing here is a real credential.
#![allow(dead_code)]

pub mod db;

use aap_core::{jws, SigningKey, VerifyingKey};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD as B64};
use base64::Engine as _;
use ciborium::value::Value;
use p256::ecdsa::{signature::Signer, Signature};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CustomExtension, DistinguishedName, DnType,
    IsCa, KeyPair, PKCS_ECDSA_P256_SHA256,
};
use serde_json::json;
use sha2::{Digest, Sha256};

use aap_issuer_service::appattest::{AAGUID_DEVELOPMENT, AAGUID_PRODUCTION};

pub const APP_ID: &str = "ABCDE12345.com.example.issuer";
pub const OTHER_APP_ID: &str = "ZZZZZ99999.com.example.other";
/// A moment inside every synthetic certificate's validity window.
pub const NOW: i64 = 1_800_000_000; // 2027-01-15

pub struct Pki {
    pub root_pem: String,
    inter: Certificate,
    inter_key: KeyPair,
}

fn ca_params(cn: &str) -> CertificateParams {
    let mut p = CertificateParams::new(vec![]).unwrap();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, cn);
    p.distinguished_name = dn;
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.not_before = rcgen::date_time_ymd(2020, 1, 1);
    p.not_after = rcgen::date_time_ymd(2100, 1, 1);
    p
}

impl Pki {
    pub fn new() -> Pki {
        let root_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let root = ca_params("Test App Attestation Root")
            .self_signed(&root_key)
            .unwrap();
        let inter_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let inter = ca_params("Test App Attestation CA 1")
            .signed_by(&inter_key, &root, &root_key)
            .unwrap();
        Pki {
            root_pem: root.pem(),
            inter,
            inter_key,
        }
    }

    pub fn root_pem(&self) -> &[u8] {
        self.root_pem.as_bytes()
    }
}

/// A fake iOS app instance: holds the App Attest key.
pub struct AppAttestDevice {
    pub sk: p256::ecdsa::SigningKey,
    pub key_id: Vec<u8>,
}

impl AppAttestDevice {
    pub fn new() -> Self {
        let sk = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        let pt = sk.verifying_key().to_encoded_point(false);
        AppAttestDevice {
            key_id: Sha256::digest(pt.as_bytes()).to_vec(),
            sk,
        }
    }
    pub fn key_id_b64(&self) -> String {
        STANDARD.encode(&self.key_id)
    }
}

#[derive(Clone)]
pub struct Opts {
    pub app_id: String,
    pub counter: u32,
    pub aaguid: [u8; 16],
    pub credential_id: Option<Vec<u8>>,
    /// Corrupt the nonce in the certificate extension.
    pub bad_nonce: bool,
    pub leaf_is_ca: bool,
    pub fmt: &'static str,
    pub x5c_len: usize,
}

impl Default for Opts {
    fn default() -> Self {
        Opts {
            app_id: APP_ID.into(),
            counter: 0,
            aaguid: *AAGUID_PRODUCTION,
            credential_id: None,
            bad_nonce: false,
            leaf_is_ca: false,
            fmt: "apple-appattest",
            x5c_len: 2,
        }
    }
}

pub fn dev_opts() -> Opts {
    Opts {
        aaguid: *AAGUID_DEVELOPMENT,
        ..Opts::default()
    }
}

pub fn auth_data_attestation(dev: &AppAttestDevice, o: &Opts) -> Vec<u8> {
    let mut d = Sha256::digest(o.app_id.as_bytes()).to_vec();
    d.push(0x40);
    d.extend_from_slice(&o.counter.to_be_bytes());
    d.extend_from_slice(&o.aaguid);
    let cred = o
        .credential_id
        .clone()
        .unwrap_or_else(|| dev.key_id.clone());
    d.extend_from_slice(&(cred.len() as u16).to_be_bytes());
    d.extend_from_slice(&cred);
    d.extend_from_slice(&[0xa5, 0x01, 0x02]); // COSE key stub, ignored by the verifier
    d
}

pub fn cbor(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(v, &mut out).unwrap();
    out
}

fn text(s: &str) -> Value {
    Value::Text(s.into())
}

/// Builds an attestation object for `client_data_hash`.
pub fn attestation(pki: &Pki, dev: &AppAttestDevice, client_data_hash: &[u8], o: &Opts) -> Vec<u8> {
    let auth_data = auth_data_attestation(dev, o);
    let mut nonce: [u8; 32] = Sha256::new()
        .chain_update(&auth_data)
        .chain_update(client_data_hash)
        .finalize()
        .into();
    if o.bad_nonce {
        nonce[0] ^= 0xff;
    }
    let mut ext = vec![0x30, 36, 0xa1, 34, 0x04, 32];
    ext.extend_from_slice(&nonce);

    let leaf_key = KeyPair::try_from(dev.sk.to_pkcs8_der_bytes().as_slice()).unwrap();
    let mut p = CertificateParams::new(vec![]).unwrap();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "test credential certificate");
    p.distinguished_name = dn;
    p.not_before = rcgen::date_time_ymd(2020, 1, 1);
    p.not_after = rcgen::date_time_ymd(2100, 1, 1);
    p.is_ca = if o.leaf_is_ca {
        IsCa::Ca(BasicConstraints::Unconstrained)
    } else {
        IsCa::NoCa
    };
    p.custom_extensions.push(CustomExtension::from_oid_content(
        &[1, 2, 840, 113635, 100, 8, 2],
        ext,
    ));
    let leaf = p.signed_by(&leaf_key, &pki.inter, &pki.inter_key).unwrap();

    let mut chain = vec![
        Value::Bytes(leaf.der().to_vec()),
        Value::Bytes(pki.inter.der().to_vec()),
    ];
    chain.truncate(o.x5c_len);
    cbor(&Value::Map(vec![
        (text("fmt"), text(o.fmt)),
        (
            text("attStmt"),
            Value::Map(vec![
                (text("x5c"), Value::Array(chain)),
                (text("receipt"), Value::Bytes(vec![1, 2, 3])),
            ]),
        ),
        (text("authData"), Value::Bytes(auth_data)),
    ]))
}

trait Pkcs8Bytes {
    fn to_pkcs8_der_bytes(&self) -> Vec<u8>;
}
impl Pkcs8Bytes for p256::ecdsa::SigningKey {
    fn to_pkcs8_der_bytes(&self) -> Vec<u8> {
        use p256::pkcs8::EncodePrivateKey;
        self.to_pkcs8_der().unwrap().as_bytes().to_vec()
    }
}

/// Bare 37-byte authenticatorData with the AT flag set, as iOS 27 produces.
pub fn assertion_auth_data(app_id: &str, counter: u32) -> Vec<u8> {
    let mut d = Sha256::digest(app_id.as_bytes()).to_vec();
    d.push(0x40);
    d.extend_from_slice(&counter.to_be_bytes());
    d
}

/// Returns the high-S twin of a signature (still valid for ECDSA).
pub fn to_high_s(sig: Signature) -> Signature {
    let low = sig.normalize_s().unwrap_or(sig);
    let neg = p256::NonZeroScalar::new(-*low.s()).unwrap();
    Signature::from_scalars(*low.r(), neg).unwrap()
}

pub fn assertion_with(
    dev: &AppAttestDevice,
    app_id: &str,
    counter: u32,
    client_data_hash: &[u8],
    high_s: bool,
) -> Vec<u8> {
    let auth_data = assertion_auth_data(app_id, counter);
    let nonce = Sha256::new()
        .chain_update(&auth_data)
        .chain_update(client_data_hash)
        .finalize();
    let mut sig: Signature = dev.sk.sign(&nonce);
    if high_s {
        sig = to_high_s(sig);
    }
    cbor(&Value::Map(vec![
        (
            text("signature"),
            Value::Bytes(sig.to_der().as_bytes().to_vec()),
        ),
        (text("authenticatorData"), Value::Bytes(auth_data)),
    ]))
}

pub fn assertion(dev: &AppAttestDevice, counter: u32, client_data_hash: &[u8]) -> Vec<u8> {
    assertion_with(dev, APP_ID, counter, client_data_hash, false)
}

pub fn mandate_digest(mandate: &[u8]) -> [u8; 32] {
    Sha256::digest(mandate).into()
}

// ------------------------------------------------------ enrollment builders

pub struct Principal {
    pub sk: p256::ecdsa::SigningKey,
}

impl Principal {
    pub fn new() -> Self {
        Principal {
            sk: p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng),
        }
    }
    pub fn jwk(&self) -> serde_json::Value {
        let j = jws::public_key_to_jwk(&VerifyingKey::P256(*self.sk.verifying_key()));
        json!({"kty": j.kty, "crv": j.crv, "x": j.x, "y": j.y})
    }
    pub fn thumbprint(&self) -> [u8; 32] {
        let j = self.jwk();
        aap_issuer_service::jwk::thumbprint(j["x"].as_str().unwrap(), j["y"].as_str().unwrap())
    }
    pub fn sign(&self, payload: &serde_json::Value) -> String {
        jws::sign(payload, &SigningKey::P256(self.sk.clone())).unwrap()
    }
}

pub fn client_data_hash(challenge: &[u8], thumbprint: &[u8]) -> Vec<u8> {
    Sha256::new()
        .chain_update(challenge)
        .chain_update(thumbprint)
        .finalize()
        .to_vec()
}

/// Everything needed to build (and tamper with) an enrollment request.
pub struct Enrollment<'a> {
    pub pki: &'a Pki,
    pub app: &'a AppAttestDevice,
    pub principal: &'a Principal,
    pub challenge: Vec<u8>,
    pub opts: Opts,
    /// Principal key used for the PoP signature (defaults to `principal`).
    pub pop_signer: Option<&'a Principal>,
    pub pop_thumbprint: Option<String>,
    pub pop_challenge: Option<String>,
    pub pop_key_id: Option<String>,
    pub pop_purpose: Option<String>,
    /// Thumbprint mixed into clientDataHash (defaults to the real one).
    pub cdh_thumbprint: Option<[u8; 32]>,
}

impl<'a> Enrollment<'a> {
    pub fn new(
        pki: &'a Pki,
        app: &'a AppAttestDevice,
        principal: &'a Principal,
        challenge: Vec<u8>,
    ) -> Self {
        Enrollment {
            pki,
            app,
            principal,
            challenge,
            opts: Opts::default(),
            pop_signer: None,
            pop_thumbprint: None,
            pop_challenge: None,
            pop_key_id: None,
            pop_purpose: None,
            cdh_thumbprint: None,
        }
    }

    pub fn body(&self, challenge_id: &str) -> serde_json::Value {
        let tp = self
            .cdh_thumbprint
            .unwrap_or_else(|| self.principal.thumbprint());
        let cdh = client_data_hash(&self.challenge, &tp);
        let att = attestation(self.pki, self.app, &cdh, &self.opts);
        let pop = self.pop_signer.unwrap_or(self.principal).sign(&json!({
            "purpose": self.pop_purpose.clone().unwrap_or_else(|| "aap-enrollment-pop/v1".into()),
            "challenge": self.pop_challenge.clone().unwrap_or_else(|| B64.encode(&self.challenge)),
            "key_id": self.pop_key_id.clone().unwrap_or_else(|| self.app.key_id_b64()),
            "jwk_thumbprint": self.pop_thumbprint.clone().unwrap_or_else(|| B64.encode(self.principal.thumbprint())),
        }));
        json!({
            "challenge_id": challenge_id,
            "key_id": self.app.key_id_b64(),
            "attestation": B64.encode(att),
            "principal_jwk": self.principal.jwk(),
            "pop_jws": pop,
        })
    }
}
