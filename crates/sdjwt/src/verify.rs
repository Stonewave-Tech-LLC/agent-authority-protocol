//! Verification: the only way from wire data to a [`VerifiedChain`].
//!
//! `Unverified<Presentation>` is what parsing yields. `VerifiedChain` has
//! private fields and no constructor other than [`Unverified::verify`], so
//! code that takes a `VerifiedChain` cannot be handed unverified data — the
//! same typestate rule `aap-core`'s `token.rs` enforces for v0 tokens.
//!
//! Steps (RFC 9901 §7.1/§7.3 and draft-gco-oauth-delegate-sd-jwt
//! "Verification"), every one fail-closed:
//!
//! 1. The verifier's policy decides the expected shape ([`KeyBinding`]);
//!    the presentation's shape must match it, never the other way round.
//! 2. Root: `typ` allowed, `alg` matches the issuer key, signature, `_sd_alg`
//!    supported, disclosures processed, `exp`/`nbf` valid. In the
//!    [`RootForm::DelegatePayload`] form (AP2's user-signed mandates) the
//!    root's claims are its single disclosed Delegate Payload, exactly as
//!    for a link.
//! 3. Each link, in order: `typ` allowed *for its position*, signature by the
//!    previous element's `cnf` key, exactly one of `sd_hash` /
//!    `issuer_jwt_hash` matching the previous element (hash of the previous
//!    element's `_sd_alg`), `iat`/`aud`/`nonce` present, disclosures
//!    processed, exactly one Delegate Payload disclosed, `cnf` present iff
//!    the link delegates further, `exp`/`nbf` valid.
//! 4. The final binding (KB-JWT, or the terminal link itself): `aud` and
//!    `nonce` equal to the verifier's, `iat` inside the freshness window.
//!
//! Format only: what the claims *mean* (constraints, mandate types, status)
//! is for `aap-authority` to evaluate on the `VerifiedChain`.

use serde_json::Value;

use crate::error::{Error, ErrorKind, Position};
use crate::hash::SdAlg;
use crate::jws::{Jws, Object};
use crate::keys::VerifyingKey;
use crate::presentation::Presentation;
use crate::process::{element_digest, process};
use crate::sdjwt::SdJwt;
use crate::typ;

/// Wire data that has not been verified. Inspect it only to decide which
/// issuer key to verify against.
#[derive(Debug, Clone)]
pub struct Unverified<T> {
    inner: T,
}

impl<T> Unverified<T> {
    pub fn new(inner: T) -> Self {
        Unverified { inner }
    }

    pub fn inner(&self) -> &T {
        &self.inner
    }

    /// For holders that want to select disclosures or delegate further.
    /// Never a shortcut to trust: nothing but `verify` yields a
    /// `VerifiedChain`.
    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl Unverified<Presentation> {
    pub fn parse(input: &str) -> Result<Self, Error> {
        Ok(Unverified::new(Presentation::parse(input)?))
    }

    pub fn verify(
        &self,
        issuer_key: &VerifyingKey,
        options: &VerifyOptions,
    ) -> Result<VerifiedChain, Error> {
        verify(&self.inner, issuer_key, options)
    }
}

/// What the verifier requires at the end of the presentation. Decided by
/// the verifier's policy, never by what the holder happened to send
/// (RFC 9901 §7.3 step 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyBinding {
    /// No key binding: the presentation must end in `~` (RFC 9901 §4). Also
    /// what a holder uses to check an SD-JWT it was just issued.
    NotRequired,
    /// The presentation must end in a KB-JWT (`typ: kb+jwt`) signed by the
    /// last element's `cnf` key: an SD-JWT+KB or a dSD-JWT+KB.
    KbJwt { audience: String, nonce: String },
    /// The presentation must end in a terminal KB-SD-JWT (`typ: kb+sd-jwt`,
    /// no `cnf`) whose own `aud`/`nonce`/`iat` bind it to this transaction.
    /// This is AP2's closed mandate: the agent signs it with the key the
    /// open mandate's `cnf` names, and no further KB-JWT follows.
    TerminalLink { audience: String, nonce: String },
}

/// How the Issuer-signed JWT carries its claims. Chosen by the verifier's
/// policy, like [`KeyBinding`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RootForm {
    /// The JWT payload is the claim set (an SD-JWT VC user credential).
    #[default]
    Credential,
    /// The JWT payload holds only `delegate_payload` and `_sd_alg`, and the
    /// claims are its single disclosed element, as in a KB-SD-JWT. This is
    /// how the AP2 reference SDK issues a user-signed mandate (an open
    /// mandate, or a human-present closed mandate): there is no separate
    /// user credential, and the "issuer" key is the user's own key.
    DelegatePayload,
}

#[derive(Debug, Clone)]
pub struct VerifyOptions {
    /// The verifier's clock, seconds since the epoch.
    pub now: i64,
    /// Allowed `typ` values of the Issuer-signed JWT, e.g. `dc+sd-jwt`.
    pub root_typ: Vec<String>,
    pub root_form: RootForm,
    pub key_binding: KeyBinding,
    /// Clock skew tolerated on `exp` and `nbf`, in seconds.
    pub leeway: i64,
    /// How old the final binding's `iat` may be, in seconds.
    pub max_age: i64,
    /// How far in the future any `iat` may be, in seconds.
    pub max_future: i64,
    /// Require `exp` on the root and on every delegating link. An open
    /// mandate without expiry would be valid forever.
    pub require_exp: bool,
    /// Upper bound on KB-SD-JWT links, so a hostile presentation cannot make
    /// the verifier do unbounded signature checks. Delegation depth *policy*
    /// belongs to the constraint layer.
    pub max_links: usize,
}

impl VerifyOptions {
    /// Defaults: no leeway on `exp`/`nbf`, final binding at most 5 minutes
    /// old and 30 seconds in the future, `exp` required, at most 16 links.
    pub fn new(now: i64, root_typ: impl Into<String>, key_binding: KeyBinding) -> Self {
        VerifyOptions {
            now,
            root_typ: vec![root_typ.into()],
            root_form: RootForm::Credential,
            key_binding,
            leeway: 0,
            max_age: 300,
            max_future: 30,
            require_exp: true,
            max_links: 16,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkKind {
    /// The Issuer-signed JWT.
    Root,
    /// A KB-SD-JWT+KB (`typ: kb-sd-jwt+kb`): delegates to the key in its
    /// Delegate Payload's `cnf`. An open mandate.
    Delegation,
    /// A KB-SD-JWT (`typ: kb+sd-jwt`) without `cnf`. A closed mandate.
    Terminal,
}

/// One verified element of the chain.
#[derive(Debug, Clone)]
pub struct VerifiedLink {
    position: Position,
    kind: LinkKind,
    header: Object,
    claims: Object,
    envelope: Object,
    cnf: Option<VerifyingKey>,
    sd_alg: SdAlg,
    sd_jwt: String,
}

impl VerifiedLink {
    pub fn position(&self) -> Position {
        self.position
    }

    pub fn kind(&self) -> LinkKind {
        self.kind
    }

    pub fn header(&self) -> &Object {
        &self.header
    }

    /// The claims this element vouches for: the Processed SD-JWT Payload of
    /// the root, or the single disclosed Delegate Payload of a link.
    pub fn claims(&self) -> &Object {
        &self.claims
    }

    /// For a link, the processed KB-SD-JWT claims around the Delegate
    /// Payload (`iat`, `aud`, `nonce`, `sd_hash`/`issuer_jwt_hash`). For a
    /// [`RootForm::DelegatePayload`] root, whatever its JWT carries besides
    /// the Delegate Payload. Empty for a credential root.
    pub fn envelope(&self) -> &Object {
        &self.envelope
    }

    /// The key from `cnf`, when this element names one this crate supports.
    pub fn cnf(&self) -> Option<&VerifyingKey> {
        self.cnf.as_ref()
    }

    pub fn sd_alg(&self) -> SdAlg {
        self.sd_alg
    }

    /// This element as presented, `<JWT>~<D>~...~`. Its hash (with
    /// `sd_alg`) is what the next element's `sd_hash` commits to.
    pub fn sd_jwt(&self) -> &str {
        &self.sd_jwt
    }
}

/// The final KB-JWT, verified.
#[derive(Debug, Clone)]
pub struct VerifiedKeyBinding {
    header: Object,
    claims: Object,
}

impl VerifiedKeyBinding {
    pub fn header(&self) -> &Object {
        &self.header
    }

    pub fn claims(&self) -> &Object {
        &self.claims
    }
}

/// A presentation whose every signature, binding hash, disclosure, `typ`
/// and validity claim has been checked. Constructible only by
/// [`Unverified::verify`].
#[derive(Debug, Clone)]
pub struct VerifiedChain {
    links: Vec<VerifiedLink>,
    key_binding: Option<VerifiedKeyBinding>,
    serialized: String,
}

impl VerifiedChain {
    pub fn root(&self) -> &VerifiedLink {
        &self.links[0]
    }

    /// The KB-SD-JWT links after the root, in order.
    pub fn delegations(&self) -> &[VerifiedLink] {
        &self.links[1..]
    }

    /// Root first, then every link.
    pub fn links(&self) -> &[VerifiedLink] {
        &self.links
    }

    /// The last element: the closed mandate in a `TerminalLink`
    /// presentation, the delegate's credential otherwise.
    pub fn leaf(&self) -> &VerifiedLink {
        self.links.last().expect("a chain always has a root")
    }

    pub fn key_binding(&self) -> Option<&VerifiedKeyBinding> {
        self.key_binding.as_ref()
    }

    /// The presentation exactly as received.
    pub fn serialized(&self) -> &str {
        &self.serialized
    }
}

fn verify(
    p: &Presentation,
    issuer_key: &VerifyingKey,
    opts: &VerifyOptions,
) -> Result<VerifiedChain, Error> {
    let n = p.links().len();
    if n > opts.max_links {
        return Err(ErrorKind::Malformed("more links than max_links").into());
    }
    match (&opts.key_binding, p.key_binding()) {
        (KeyBinding::NotRequired, Some(_)) | (KeyBinding::TerminalLink { .. }, Some(_)) => {
            return Err(ErrorKind::UnexpectedKeyBinding.at(Position::KeyBinding))
        }
        (KeyBinding::KbJwt { .. }, None) => {
            return Err(ErrorKind::MissingKeyBinding.at(Position::KeyBinding))
        }
        (KeyBinding::TerminalLink { .. }, None) if n == 0 => {
            return Err(ErrorKind::MissingKeyBinding.at(Position::Root))
        }
        _ => {}
    }
    // Does the element at `index` (0 = root) have to name a next key?
    let needs_cnf =
        |index: usize| index < n || matches!(opts.key_binding, KeyBinding::KbJwt { .. });

    let root =
        verify_root(p.root(), issuer_key, opts, needs_cnf(0)).map_err(|k| k.at(Position::Root))?;
    let mut links = vec![root];
    for (i, element) in p.links().iter().enumerate() {
        let position = Position::Link(i + 1);
        let previous = (&links[i], if i == 0 { p.root() } else { &p.links()[i - 1] });
        let link = verify_link(
            element,
            previous,
            i + 1 == n,
            opts,
            needs_cnf(i + 1),
            position,
        )
        .map_err(|k| k.at(position))?;
        links.push(link);
    }

    let key_binding = match (&opts.key_binding, p.key_binding()) {
        (KeyBinding::KbJwt { audience, nonce }, Some(kb)) => Some(
            verify_kb_jwt(
                kb,
                links.last().expect("root"),
                p.last(),
                audience,
                nonce,
                opts,
            )
            .map_err(|k| k.at(Position::KeyBinding))?,
        ),
        _ => None,
    };

    Ok(VerifiedChain {
        links,
        key_binding,
        serialized: p.serialize(),
    })
}

fn verify_root(
    root: &SdJwt,
    issuer_key: &VerifyingKey,
    opts: &VerifyOptions,
    needs_cnf: bool,
) -> Result<VerifiedLink, ErrorKind> {
    let allowed: Vec<&str> = opts.root_typ.iter().map(String::as_str).collect();
    root.jws().check_typ(&allowed)?;
    root.jws().verify(issuer_key)?;
    let sd_alg = SdAlg::of_payload(root.jws().payload())?;
    let processed = process(root.jws().payload(), root.disclosures(), sd_alg)?.claims;
    let (claims, envelope) = match opts.root_form {
        RootForm::Credential => (processed, Object::new()),
        RootForm::DelegatePayload => {
            check_raw_delegate_payload(root.jws().payload())?;
            let mut envelope = processed;
            let claims = take_delegate_payload(&mut envelope)?;
            check_validity(&envelope, opts, false)?;
            (claims, envelope)
        }
    };
    check_validity(&claims, opts, opts.require_exp)?;
    let cnf = read_cnf(&claims, needs_cnf)?;
    Ok(VerifiedLink {
        position: Position::Root,
        kind: LinkKind::Root,
        header: root.jws().header().clone(),
        claims,
        envelope,
        cnf,
        sd_alg,
        sd_jwt: root.serialize(),
    })
}

fn verify_link(
    element: &SdJwt,
    (prev, prev_element): (&VerifiedLink, &SdJwt),
    is_last: bool,
    opts: &VerifyOptions,
    needs_cnf: bool,
    position: Position,
) -> Result<VerifiedLink, ErrorKind> {
    let jws = element.jws();
    // typ per position (draft "Verification" steps 3.5 and 4.2).
    let allowed: &[&str] = match (&opts.key_binding, is_last) {
        (KeyBinding::NotRequired, true) => &[
            typ::KB_SD_JWT,
            typ::KB_SD_JWT_KB,
            typ::KB_SD_JWT_KB_DRAFT_00,
        ],
        (KeyBinding::TerminalLink { .. }, true) => &[typ::KB_SD_JWT],
        _ => &[typ::KB_SD_JWT_KB, typ::KB_SD_JWT_KB_DRAFT_00],
    };
    jws.check_typ(allowed)?;
    let key = prev.cnf.as_ref().ok_or(ErrorKind::MissingCnf)?;
    jws.verify(key)?;

    let payload = jws.payload();
    check_hash_binding(payload, prev_element, prev.sd_alg)?;
    let iat = numeric(payload, "iat")?.ok_or(ErrorKind::InvalidClaim("iat"))?;
    let aud = single_string(payload, "aud")?;
    let nonce = single_string(payload, "nonce")?;

    check_raw_delegate_payload(payload)?;
    let sd_alg = SdAlg::of_payload(payload)?;
    let mut envelope = process(payload, element.disclosures(), sd_alg)?.claims;
    let claims = take_delegate_payload(&mut envelope)?;

    let kind = if jws.check_typ(&[typ::KB_SD_JWT]).is_ok() {
        LinkKind::Terminal
    } else {
        LinkKind::Delegation
    };
    let cnf = match kind {
        LinkKind::Terminal if claims.contains_key("cnf") => return Err(ErrorKind::UnexpectedCnf),
        LinkKind::Terminal => None,
        _ => {
            if !claims.contains_key("cnf") {
                return Err(ErrorKind::MissingCnf);
            }
            read_cnf(&claims, needs_cnf)?
        }
    };

    check_validity(&envelope, opts, false)?;
    check_validity(
        &claims,
        opts,
        opts.require_exp && kind == LinkKind::Delegation,
    )?;
    match (&opts.key_binding, is_last) {
        (
            KeyBinding::TerminalLink {
                audience,
                nonce: expected,
            },
            true,
        ) => check_transaction(iat, aud, nonce, audience, expected, opts)?,
        _ if iat > (opts.now + opts.max_future) as f64 => return Err(ErrorKind::IatOutOfWindow),
        _ => {}
    }

    Ok(VerifiedLink {
        position,
        kind,
        header: jws.header().clone(),
        claims,
        envelope,
        cnf,
        sd_alg,
        sd_jwt: element.serialize(),
    })
}

fn verify_kb_jwt(
    kb: &Jws,
    last: &VerifiedLink,
    last_element: &SdJwt,
    audience: &str,
    expected_nonce: &str,
    opts: &VerifyOptions,
) -> Result<VerifiedKeyBinding, ErrorKind> {
    kb.check_typ(&[typ::KB_JWT])?;
    let key = last.cnf.as_ref().ok_or(ErrorKind::MissingCnf)?;
    kb.verify(key)?;
    let claims = kb.payload();
    let sd_hash = single_string(claims, "sd_hash")?;
    if sd_hash != last.sd_alg.digest(&last_element.serialize()) {
        return Err(ErrorKind::BindingMismatch("sd_hash"));
    }
    let iat = numeric(claims, "iat")?.ok_or(ErrorKind::InvalidClaim("iat"))?;
    let aud = single_string(claims, "aud")?;
    let nonce = single_string(claims, "nonce")?;
    check_transaction(iat, aud, nonce, audience, expected_nonce, opts)?;
    check_validity(claims, opts, false)?;
    Ok(VerifiedKeyBinding {
        header: kb.header().clone(),
        claims: claims.clone(),
    })
}

/// The raw `delegate_payload`, before disclosures: a non-empty array, and
/// with more than one element every element must be a digest.
fn check_raw_delegate_payload(payload: &Object) -> Result<(), ErrorKind> {
    let raw = payload
        .get("delegate_payload")
        .and_then(Value::as_array)
        .filter(|a| !a.is_empty())
        .ok_or(ErrorKind::DelegatePayload(
            "missing or not a non-empty array",
        ))?;
    if raw.len() > 1 {
        for item in raw {
            if element_digest(item)?.is_none() {
                return Err(ErrorKind::DelegatePayload(
                    "with several elements, each must be a disclosure digest",
                ));
            }
        }
    }
    Ok(())
}

/// Removes the processed `delegate_payload` from `envelope` and returns its
/// single disclosed element.
fn take_delegate_payload(envelope: &mut Object) -> Result<Object, ErrorKind> {
    let claims = match envelope.remove("delegate_payload") {
        Some(Value::Array(items)) => match <[Value; 1]>::try_from(items) {
            Ok([Value::Object(claims)]) => claims,
            Ok(_) => {
                return Err(ErrorKind::DelegatePayload(
                    "disclosed element is not an object",
                ))
            }
            Err(_) => {
                return Err(ErrorKind::DelegatePayload(
                    "exactly one element must be disclosed",
                ))
            }
        },
        _ => {
            return Err(ErrorKind::DelegatePayload(
                "missing or not a non-empty array",
            ))
        }
    };
    // "All claims ... except _sd_alg MUST instead be claims in the Delegate
    // Payload": an _sd_alg in there would look like it applies, and does not.
    if claims.contains_key("_sd_alg") {
        return Err(ErrorKind::ReservedName("_sd_alg".into()));
    }
    Ok(claims)
}

/// Exactly one of `sd_hash` / `issuer_jwt_hash`, matching the previous
/// element, hashed with the previous element's `_sd_alg`. Both present is
/// rejected as ambiguous; the draft only defines either-or.
fn check_hash_binding(payload: &Object, prev: &SdJwt, alg: SdAlg) -> Result<(), ErrorKind> {
    match (payload.get("sd_hash"), payload.get("issuer_jwt_hash")) {
        (Some(_), None) => {
            if single_string(payload, "sd_hash")? != alg.digest(&prev.serialize()) {
                return Err(ErrorKind::BindingMismatch("sd_hash"));
            }
        }
        (None, Some(_)) => {
            if single_string(payload, "issuer_jwt_hash")? != alg.digest(prev.jwt()) {
                return Err(ErrorKind::BindingMismatch("issuer_jwt_hash"));
            }
        }
        _ => return Err(ErrorKind::AmbiguousBinding),
    }
    Ok(())
}

fn check_transaction(
    iat: f64,
    aud: &str,
    nonce: &str,
    expected_aud: &str,
    expected_nonce: &str,
    opts: &VerifyOptions,
) -> Result<(), ErrorKind> {
    if aud != expected_aud {
        return Err(ErrorKind::AudienceMismatch);
    }
    if nonce != expected_nonce {
        return Err(ErrorKind::NonceMismatch);
    }
    let now = opts.now as f64;
    if iat < now - opts.max_age as f64 || iat > now + opts.max_future as f64 {
        return Err(ErrorKind::IatOutOfWindow);
    }
    Ok(())
}

/// `exp` and `nbf` against the verifier's clock, when present (RFC 9901
/// §7.1 step 6). Present but not a number is an error, not "absent".
fn check_validity(
    claims: &Object,
    opts: &VerifyOptions,
    require_exp: bool,
) -> Result<(), ErrorKind> {
    let now = opts.now as f64;
    let leeway = opts.leeway as f64;
    match numeric(claims, "exp")? {
        Some(exp) if now >= exp + leeway => return Err(ErrorKind::Expired),
        None if require_exp => return Err(ErrorKind::MissingExp),
        _ => {}
    }
    if let Some(nbf) = numeric(claims, "nbf")? {
        if now + leeway < nbf {
            return Err(ErrorKind::NotYetValid);
        }
    }
    Ok(())
}

/// A NumericDate claim (RFC 7519 §2): a JSON number, possibly fractional.
fn numeric(claims: &Object, name: &'static str) -> Result<Option<f64>, ErrorKind> {
    match claims.get(name) {
        None => Ok(None),
        Some(Value::Number(n)) => n.as_f64().map(Some).ok_or(ErrorKind::InvalidClaim(name)),
        Some(_) => Err(ErrorKind::InvalidClaim(name)),
    }
}

/// A required claim that must be a single string (RFC 9901 §4.3 for `aud`).
fn single_string<'a>(claims: &'a Object, name: &'static str) -> Result<&'a str, ErrorKind> {
    claims
        .get(name)
        .and_then(Value::as_str)
        .ok_or(ErrorKind::InvalidClaim(name))
}

/// The `cnf` key. Required when a next element must be verified with it;
/// otherwise a `cnf` this crate cannot use is left in the claims, unread.
fn read_cnf(claims: &Object, required: bool) -> Result<Option<VerifyingKey>, ErrorKind> {
    match (claims.get("cnf"), required) {
        (Some(cnf), true) => VerifyingKey::from_cnf(cnf).map(Some),
        (Some(cnf), false) => Ok(VerifyingKey::from_cnf(cnf).ok()),
        (None, true) => Err(ErrorKind::MissingCnf),
        (None, false) => Ok(None),
    }
}
