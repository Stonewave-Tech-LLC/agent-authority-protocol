//! Apple App Attest verification, following "Validating Apps That Connect to
//! Your Server" (Apple Developer Documentation): attestation steps 1–9 once
//! at enrollment, assertion steps for every signed payload afterwards.
//!
//! Ported from the Spike S1 verifier. What this proves, and what it does not
//! (see the spike notes): the attestation certifies the *App Attest key* of a
//! genuine instance of `TEAMID.bundleId` on genuine Apple hardware. Anything
//! else, such as the Secure Enclave principal key, is just data that instance
//! chose to hash into `clientDataHash`. The assurance recorded for it is
//! therefore `app_attest`, never a claim about the principal key's flags.
//!
//! Findings from real hardware that shape this code:
//! * the leaf credCert is valid for only ~3 days, so the chain is verified
//!   once at enrollment and only the extracted public key is kept;
//! * assertion `authenticatorData` is a bare 37 bytes even when the AT flag is
//!   set (iOS 27), so the flag is never trusted, only the length;
//! * `keyId` is standard base64, JOSE is base64url;
//! * ES256 signatures are often high-S, so low-S is never required.

use ciborium::value::Value;
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;

/// Apple App Attestation Root CA (public, pinned). SHA-256 of the DER is
/// asserted in the tests.
pub const APPLE_APP_ATTEST_ROOT_PEM: &[u8] =
    include_bytes!("../certs/Apple_App_Attestation_Root_CA.pem");
const NONCE_EXTENSION_OID: &str = "1.2.840.113635.100.8.2";
pub const AAGUID_DEVELOPMENT: &[u8; 16] = b"appattestdevelop";
pub const AAGUID_PRODUCTION: &[u8; 16] = b"appattest\0\0\0\0\0\0\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Environment {
    Development,
    Production,
}

impl Environment {
    pub fn as_str(self) -> &'static str {
        match self {
            Environment::Development => "development",
            Environment::Production => "production",
        }
    }
}

/// Every way verification can fail. `code()` is a stable, content-free
/// identifier that is safe to log, audit and return to the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AppAttestError {
    #[error("not valid CBOR")]
    Cbor,
    #[error("unexpected attestation structure")]
    Structure,
    #[error("unexpected attestation format")]
    Format,
    #[error("certificate could not be parsed")]
    CertParse,
    #[error("certificate chain does not lead to the Apple root")]
    ChainInvalid,
    #[error("certificate outside its validity period")]
    CertExpired,
    #[error("nonce extension missing or malformed")]
    NonceExtension,
    #[error("nonce does not match authData and clientDataHash")]
    NonceMismatch,
    #[error("key id does not match the credential certificate key")]
    KeyIdMismatch,
    #[error("authData malformed")]
    AuthData,
    #[error("rpIdHash is not an allowed app id")]
    RpIdNotAllowed,
    #[error("attestation counter is not zero")]
    CounterNotZero,
    #[error("unknown aaguid")]
    AaguidUnknown,
    #[error("development environment not accepted")]
    DevelopmentNotAccepted,
    #[error("credentialId does not match key id")]
    CredentialIdMismatch,
    #[error("signature invalid")]
    BadSignature,
    #[error("assertion rpIdHash mismatch")]
    AssertionRpIdMismatch,
    #[error("stored public key unusable")]
    BadPublicKey,
}

impl AppAttestError {
    pub fn code(self) -> &'static str {
        match self {
            Self::Cbor => "cbor",
            Self::Structure => "structure",
            Self::Format => "format",
            Self::CertParse => "cert_parse",
            Self::ChainInvalid => "chain_invalid",
            Self::CertExpired => "cert_expired",
            Self::NonceExtension => "nonce_extension",
            Self::NonceMismatch => "nonce_mismatch",
            Self::KeyIdMismatch => "key_id_mismatch",
            Self::AuthData => "auth_data",
            Self::RpIdNotAllowed => "rp_id_not_allowed",
            Self::CounterNotZero => "counter_not_zero",
            Self::AaguidUnknown => "aaguid_unknown",
            Self::DevelopmentNotAccepted => "development_not_accepted",
            Self::CredentialIdMismatch => "credential_id_mismatch",
            Self::BadSignature => "bad_signature",
            Self::AssertionRpIdMismatch => "assertion_rp_id_mismatch",
            Self::BadPublicKey => "bad_public_key",
        }
    }
}

type Result<T> = std::result::Result<T, AppAttestError>;

/// What this deployment accepts. Differences between staging and production
/// are expressed here, as data, never as different code paths.
#[derive(Debug, Clone, Copy)]
pub struct Policy<'a> {
    /// Allowed `TEAMID.bundleId` values.
    pub app_ids: &'a [String],
    /// Accept the App Attest `development` aaguid. Staging only; the config
    /// layer refuses to start a production process with this set.
    pub allow_development: bool,
}

#[derive(Debug, Clone)]
pub struct AttestedKey {
    /// Uncompressed SEC1 point (65 bytes) of the App Attest key.
    pub public_key: Vec<u8>,
    pub environment: Environment,
    /// The allow-listed app id the rpIdHash matched.
    pub app_id: String,
}

pub struct AuthData<'a> {
    pub rp_id_hash: &'a [u8],
    pub counter: u32,
    pub aaguid: Option<&'a [u8]>,
    pub credential_id: Option<&'a [u8]>,
}

/// Parses WebAuthn-style authenticator data.
///
/// The AT flag (0x40) alone cannot decide whether attested credential data
/// follows: iOS 27 assertions are the bare 37 bytes yet still set it. So the
/// credential block is parsed only when bytes actually follow. Attestation
/// callers demand `aaguid` and `credential_id`, so nothing is lost.
pub fn parse_auth_data(data: &[u8]) -> Result<AuthData<'_>> {
    if data.len() < 37 {
        return Err(AppAttestError::AuthData);
    }
    let flags = data[32];
    let counter = u32::from_be_bytes([data[33], data[34], data[35], data[36]]);
    let (mut aaguid, mut credential_id) = (None, None);
    if flags & 0x40 != 0 && data.len() > 37 {
        if data.len() < 55 {
            return Err(AppAttestError::AuthData);
        }
        let len = u16::from_be_bytes([data[53], data[54]]) as usize;
        if data.len() < 55 + len {
            return Err(AppAttestError::AuthData);
        }
        aaguid = Some(&data[37..53]);
        credential_id = Some(&data[55..55 + len]);
    }
    Ok(AuthData {
        rp_id_hash: &data[0..32],
        counter,
        aaguid,
        credential_id,
    })
}

fn map_get<'a>(map: &'a Value, key: &str) -> Result<&'a Value> {
    map.as_map()
        .ok_or(AppAttestError::Structure)?
        .iter()
        .find(|(k, _)| k.as_text() == Some(key))
        .map(|(_, v)| v)
        .ok_or(AppAttestError::Structure)
}

fn bytes(v: &Value) -> Result<&[u8]> {
    v.as_bytes()
        .map(|b| b.as_slice())
        .ok_or(AppAttestError::Structure)
}

/// Extension value is DER `SEQUENCE { [1] EXPLICIT OCTET STRING nonce }`.
fn nonce_from_extension(value: &[u8]) -> Result<&[u8]> {
    // 30 24  A1 22  04 20 <32 bytes>
    if value.len() != 38
        || value[0] != 0x30
        || value[1] != 36
        || value[2] != 0xa1
        || value[3] != 34
        || value[4] != 0x04
        || value[5] != 32
    {
        return Err(AppAttestError::NonceExtension);
    }
    Ok(&value[6..])
}

fn sha256_concat(a: &[u8], b: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update(a)
        .chain_update(b)
        .finalize()
        .into()
}

fn match_app_id<'a>(rp_id_hash: &[u8], app_ids: &'a [String]) -> Option<&'a String> {
    app_ids
        .iter()
        .find(|id| Sha256::digest(id.as_bytes())[..] == *rp_id_hash)
}

/// Verifies an attestation against the pinned Apple root. `key_id` is the raw
/// (base64-decoded) App Attest key id; `now_unix` is the verification time.
pub fn verify_attestation(
    attestation: &[u8],
    key_id: &[u8],
    client_data_hash: &[u8],
    policy: &Policy<'_>,
    now_unix: i64,
) -> Result<AttestedKey> {
    verify_attestation_with_root(
        APPLE_APP_ATTEST_ROOT_PEM,
        attestation,
        key_id,
        client_data_hash,
        policy,
        now_unix,
    )
}

/// Same as [`verify_attestation`] with an explicit trust anchor. Production
/// code only ever passes [`APPLE_APP_ATTEST_ROOT_PEM`]; tests pass a
/// synthetic root so every rejection path can be exercised without a device.
pub fn verify_attestation_with_root(
    root_pem: &[u8],
    attestation: &[u8],
    key_id: &[u8],
    client_data_hash: &[u8],
    policy: &Policy<'_>,
    now_unix: i64,
) -> Result<AttestedKey> {
    let obj: Value = ciborium::de::from_reader(attestation).map_err(|_| AppAttestError::Cbor)?;
    if map_get(&obj, "fmt")?.as_text() != Some("apple-appattest") {
        return Err(AppAttestError::Format);
    }
    let att_stmt = map_get(&obj, "attStmt")?;
    let auth_data_bytes = bytes(map_get(&obj, "authData")?)?;
    let x5c = map_get(att_stmt, "x5c")?
        .as_array()
        .ok_or(AppAttestError::Structure)?;
    if x5c.len() != 2 {
        return Err(AppAttestError::Structure);
    }

    // 1. credCert -> intermediate -> pinned Apple root.
    let (_, leaf) =
        X509Certificate::from_der(bytes(&x5c[0])?).map_err(|_| AppAttestError::CertParse)?;
    let (_, inter) =
        X509Certificate::from_der(bytes(&x5c[1])?).map_err(|_| AppAttestError::CertParse)?;
    let (_, root_pem) = parse_x509_pem(root_pem).map_err(|_| AppAttestError::CertParse)?;
    let root = root_pem
        .parse_x509()
        .map_err(|_| AppAttestError::CertParse)?;
    root.verify_signature(None)
        .map_err(|_| AppAttestError::ChainInvalid)?;
    inter
        .verify_signature(Some(root.public_key()))
        .map_err(|_| AppAttestError::ChainInvalid)?;
    leaf.verify_signature(Some(inter.public_key()))
        .map_err(|_| AppAttestError::ChainInvalid)?;
    if !inter.is_ca() {
        return Err(AppAttestError::ChainInvalid);
    }
    if matches!(leaf.basic_constraints(), Ok(Some(bc)) if bc.value.ca) {
        return Err(AppAttestError::ChainInvalid);
    }
    // Validity is checked now, at enrollment. It is never re-checked later.
    let now = ASN1Time::from_timestamp(now_unix).map_err(|_| AppAttestError::CertExpired)?;
    if !(leaf.validity().is_valid_at(now)
        && inter.validity().is_valid_at(now)
        && root.validity().is_valid_at(now))
    {
        return Err(AppAttestError::CertExpired);
    }

    // 2-4. nonce = SHA256(authData || clientDataHash) must equal the extension.
    let nonce = sha256_concat(auth_data_bytes, client_data_hash);
    let ext = leaf
        .extensions()
        .iter()
        .find(|e| e.oid.to_id_string() == NONCE_EXTENSION_OID)
        .ok_or(AppAttestError::NonceExtension)?;
    if nonce_from_extension(ext.value)? != nonce {
        return Err(AppAttestError::NonceMismatch);
    }

    // 5. keyId = SHA256(credCert public key); the key must be a real P-256 point.
    let public_key = leaf.public_key().subject_public_key.data.to_vec();
    if public_key.len() != 65
        || public_key[0] != 0x04
        || VerifyingKey::from_sec1_bytes(&public_key).is_err()
    {
        return Err(AppAttestError::BadPublicKey);
    }
    if Sha256::digest(&public_key)[..] != *key_id {
        return Err(AppAttestError::KeyIdMismatch);
    }

    let auth = parse_auth_data(auth_data_bytes)?;
    // 6. rpIdHash must be one of the allow-listed TEAMID.bundleId values.
    let app_id = match_app_id(auth.rp_id_hash, policy.app_ids)
        .ok_or(AppAttestError::RpIdNotAllowed)?
        .clone();
    // 7. counter = 0.
    if auth.counter != 0 {
        return Err(AppAttestError::CounterNotZero);
    }
    // 8. aaguid, per environment policy.
    let environment = match auth.aaguid.ok_or(AppAttestError::AuthData)? {
        a if a == AAGUID_PRODUCTION => Environment::Production,
        a if a == AAGUID_DEVELOPMENT => {
            if !policy.allow_development {
                return Err(AppAttestError::DevelopmentNotAccepted);
            }
            Environment::Development
        }
        _ => return Err(AppAttestError::AaguidUnknown),
    };
    // 9. credentialId = keyId.
    if auth.credential_id != Some(key_id) {
        return Err(AppAttestError::CredentialIdMismatch);
    }

    Ok(AttestedKey {
        public_key,
        environment,
        app_id,
    })
}

/// Verifies one assertion against the stored App Attest public key and
/// returns the counter it carries. The caller must then advance the stored
/// counter atomically and only accept a strictly greater value.
///
/// `client_data_hash` is whatever the app passed to `generateAssertion`; for
/// mandates that is `SHA256(mandate bytes)`.
pub fn verify_assertion(
    assertion: &[u8],
    client_data_hash: &[u8],
    app_id: &str,
    public_key: &[u8],
) -> Result<u32> {
    let obj: Value = ciborium::de::from_reader(assertion).map_err(|_| AppAttestError::Cbor)?;
    let sig = Signature::from_der(bytes(map_get(&obj, "signature")?)?)
        .map_err(|_| AppAttestError::BadSignature)?;
    let auth_data_bytes = bytes(map_get(&obj, "authenticatorData")?)?;
    let nonce = sha256_concat(auth_data_bytes, client_data_hash);
    let vk = VerifyingKey::from_sec1_bytes(public_key).map_err(|_| AppAttestError::BadPublicKey)?;
    // `verify` hashes the 32-byte nonce again (ECDSA-SHA256 over the nonce,
    // as Apple specifies). Deliberately no low-S requirement.
    vk.verify(&nonce, &sig)
        .map_err(|_| AppAttestError::BadSignature)?;
    let auth = parse_auth_data(auth_data_bytes)?;
    if *auth.rp_id_hash != Sha256::digest(app_id.as_bytes())[..] {
        return Err(AppAttestError::AssertionRpIdMismatch);
    }
    Ok(auth.counter)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_ca_is_the_expected_apple_certificate() {
        let (_, pem) = parse_x509_pem(APPLE_APP_ATTEST_ROOT_PEM).unwrap();
        let fingerprint = Sha256::digest(&pem.contents);
        assert_eq!(
            fingerprint
                .iter()
                .map(|b| format!("{b:02X}"))
                .collect::<String>(),
            "1CB9823BA28BA6AD2D33A006941DE2AE4F513EF1D4E831B9F7E0FA7B6242C932"
        );
        let root = pem.parse_x509().unwrap();
        root.verify_signature(None).unwrap();
    }

    #[test]
    fn auth_data_with_attested_credential() {
        let mut d = vec![7u8; 32];
        d.push(0x40);
        d.extend_from_slice(&5u32.to_be_bytes());
        d.extend_from_slice(AAGUID_DEVELOPMENT);
        d.extend_from_slice(&3u16.to_be_bytes());
        d.extend_from_slice(&[1, 2, 3]);
        d.extend_from_slice(&[0xa5]); // start of COSE key, ignored
        let a = parse_auth_data(&d).unwrap();
        assert_eq!(a.counter, 5);
        assert_eq!(a.aaguid.unwrap(), AAGUID_DEVELOPMENT);
        assert_eq!(a.credential_id.unwrap(), &[1, 2, 3]);
    }

    #[test]
    fn assertion_auth_data_with_at_flag_but_no_credential_data() {
        // Real shape from iOS 27: flags 0x40, counter 1, nothing after it.
        let mut d = vec![0xabu8; 32];
        d.push(0x40);
        d.extend_from_slice(&1u32.to_be_bytes());
        let a = parse_auth_data(&d).unwrap();
        assert_eq!(a.counter, 1);
        assert!(a.aaguid.is_none() && a.credential_id.is_none());
    }

    #[test]
    fn truncated_auth_data_is_rejected() {
        assert_eq!(
            parse_auth_data(&[0u8; 36]).err(),
            Some(AppAttestError::AuthData)
        );
        // AT flag set, some credential bytes present but not enough.
        let mut d = vec![0u8; 32];
        d.push(0x40);
        d.extend_from_slice(&0u32.to_be_bytes());
        d.extend_from_slice(&[0u8; 10]);
        assert_eq!(parse_auth_data(&d).err(), Some(AppAttestError::AuthData));
        // credentialId length runs past the end.
        let mut d = vec![0u8; 32];
        d.push(0x40);
        d.extend_from_slice(&0u32.to_be_bytes());
        d.extend_from_slice(&[0u8; 16]);
        d.extend_from_slice(&200u16.to_be_bytes());
        d.extend_from_slice(&[0u8; 4]);
        assert_eq!(parse_auth_data(&d).err(), Some(AppAttestError::AuthData));
    }

    #[test]
    fn nonce_extension_shape() {
        let mut v = vec![0x30, 36, 0xa1, 34, 0x04, 32];
        v.extend_from_slice(&[9u8; 32]);
        assert_eq!(nonce_from_extension(&v).unwrap(), &[9u8; 32]);
        v[2] = 0xa2;
        assert!(nonce_from_extension(&v).is_err());
        assert!(nonce_from_extension(&v[..37]).is_err());
    }
}
