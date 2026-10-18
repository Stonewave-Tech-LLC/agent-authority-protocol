//! One element of a presentation: a JWT plus the disclosures that follow
//! it. The root element is the Issuer-signed JWT; every further element is a
//! KB-SD-JWT whose JWT is signed by the previous element's `cnf` key.
//!
//! Also the two builders that create elements: [`SdJwtBuilder`] for the
//! root and [`LinkBuilder`] for a delegation link.

use serde_json::{json, Value};

use crate::conceal::SdPayload;
use crate::disclosure::Disclosure;
use crate::error::{Error, ErrorKind};
use crate::hash::SdAlg;
use crate::jws::{self, Jws, Object};
use crate::keys::Signer;
use crate::pointer::{self, Path};
use crate::process::process;
use crate::typ;

#[derive(Debug, Clone)]
pub struct SdJwt {
    jws: Jws,
    disclosures: Vec<Disclosure>,
}

impl SdJwt {
    pub(crate) fn from_parts(jwt: &str, disclosures: &[&str]) -> Result<Self, ErrorKind> {
        Ok(SdJwt {
            jws: Jws::parse(jwt)?,
            disclosures: disclosures
                .iter()
                .map(|d| Disclosure::parse(d))
                .collect::<Result<_, _>>()?,
        })
    }

    pub(crate) fn jws(&self) -> &Jws {
        &self.jws
    }

    /// The compact JWT, without disclosures.
    pub fn jwt(&self) -> &str {
        self.jws.raw()
    }

    /// The JOSE header. Unverified: use it for routing (`kid`, `x5c`) only.
    pub fn header(&self) -> &Object {
        self.jws.header()
    }

    /// The JWT payload as signed, digests not yet resolved. Unverified: use
    /// it for routing (`iss`) only.
    pub fn unverified_payload(&self) -> &Object {
        self.jws.payload()
    }

    pub fn disclosures(&self) -> &[Disclosure] {
        &self.disclosures
    }

    pub fn sd_alg(&self) -> Result<SdAlg, Error> {
        Ok(SdAlg::of_payload(self.jws.payload())?)
    }

    /// `<JWT>~<D.1>~...~<D.N>~`: the element in its own SD-JWT form, which is
    /// exactly the input of the next element's `sd_hash`.
    pub fn serialize(&self) -> String {
        let mut out = String::from(self.jws.raw());
        out.push('~');
        for d in &self.disclosures {
            out.push_str(d.encoded());
            out.push('~');
        }
        out
    }

    /// Keeps only the disclosures needed to reveal the claims at `pointers`.
    ///
    /// A pointer is resolved against the payload as the holder sees it with
    /// every disclosure applied. Disclosing a pointer reveals the whole value
    /// there, including any selectively disclosable parts nested inside it,
    /// plus every disclosure on the way to it (RFC 9901 §7.2 step 2). An
    /// always-visible claim needs no disclosure but must still resolve, so a
    /// typo is an error rather than a silently smaller presentation.
    pub fn select(&self, pointers: &[&str]) -> Result<SdJwt, Error> {
        let processed = process(self.jws.payload(), &self.disclosures, self.sd_alg()?)?;
        let doc = Value::Object(processed.claims);
        let wanted: Vec<Path> = pointers
            .iter()
            .map(|p| pointer::resolve(&doc, p))
            .collect::<Result<_, _>>()?;
        let disclosures = self
            .disclosures
            .iter()
            .zip(&processed.paths)
            .filter(|(_, at)| {
                wanted
                    .iter()
                    .any(|w| at.starts_with(w) || w.starts_with(at))
            })
            .map(|(d, _)| d.clone())
            .collect();
        Ok(SdJwt {
            jws: self.jws.clone(),
            disclosures,
        })
    }
}

/// Builds an Issuer-signed SD-JWT, e.g. an SD-JWT VC user credential.
#[derive(Debug, Clone)]
pub struct SdJwtBuilder {
    typ: String,
    payload: SdPayload,
    header: Object,
    sd_alg: SdAlg,
}

impl SdJwtBuilder {
    /// `typ` is required (RFC 9901 §9.11 explicit typing), e.g.
    /// [`typ::SD_JWT_VC`]. Validity claims (`iss`, `iat`, `exp`, `cnf`, ...)
    /// go into `claims` like any other claim.
    pub fn new(typ: impl Into<String>, claims: Object) -> Self {
        SdJwtBuilder {
            typ: typ.into(),
            payload: SdPayload::new(claims),
            header: Object::new(),
            sd_alg: SdAlg::Sha256,
        }
    }

    pub fn conceal(mut self, pointer: &str) -> Self {
        self.payload = self.payload.conceal(pointer);
        self
    }

    pub fn decoys(mut self, pointer: &str, count: usize) -> Self {
        self.payload = self.payload.decoys(pointer, count);
        self
    }

    /// An extra header parameter such as `kid`. `alg`, `typ` and `crit` are
    /// set by this crate and rejected here.
    pub fn header(mut self, name: &str, value: Value) -> Self {
        self.header.insert(name.to_owned(), value);
        self
    }

    pub fn sd_alg(mut self, alg: SdAlg) -> Self {
        self.sd_alg = alg;
        self
    }

    /// Signs the JWT and returns the SD-JWT with every disclosure, as the
    /// Issuer hands it to the Holder.
    pub fn sign<S: Signer + ?Sized>(self, signer: &S) -> Result<SdJwt, Error> {
        let (mut payload, disclosures) = self.payload.build(self.sd_alg)?;
        payload.insert("_sd_alg".into(), self.sd_alg.name().into());
        let jwt = jws::sign(&self.typ, &self.header, &payload, signer)?;
        Ok(SdJwt {
            jws: Jws::parse(&jwt)?,
            disclosures,
        })
    }
}

/// How a KB-SD-JWT is bound to the element before it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HashBinding {
    /// `sd_hash` over the previous element and the disclosures presented
    /// with it. Later holders cannot change those disclosures.
    #[default]
    SdHash,
    /// `issuer_jwt_hash` over the previous element's JWT only. Later
    /// holders may drop that element's disclosures.
    IssuerJwtHash,
}

/// The transaction binding claims of a KB-JWT or KB-SD-JWT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingClaims {
    /// `aud`: who this element is for (the next delegate, or the verifier).
    pub audience: String,
    /// `nonce`: freshness, typically the recipient's challenge.
    pub nonce: String,
    /// `iat`: creation time, seconds since the epoch.
    pub issued_at: i64,
}

/// Builds a KB-SD-JWT: the delegation of the preceding element to a new
/// holder (when the Delegate Payload carries `cnf`, `typ: kb-sd-jwt+kb`) or
/// a terminal statement such as a closed mandate (no `cnf`,
/// `typ: kb+sd-jwt`). Used through [`crate::Presentation::delegate`], which
/// knows the preceding element to bind to.
#[derive(Debug, Clone)]
pub struct LinkBuilder {
    payloads: Vec<SdPayload>,
    binding: HashBinding,
    header: Object,
    sd_alg: SdAlg,
}

impl LinkBuilder {
    /// A link carrying one Delegate Payload. Its selectively disclosable
    /// parts are set on the `SdPayload`, with pointers relative to the
    /// Delegate Payload itself.
    pub fn new(payload: SdPayload) -> Self {
        LinkBuilder {
            payloads: vec![payload],
            binding: HashBinding::SdHash,
            header: Object::new(),
            sd_alg: SdAlg::Sha256,
        }
    }

    /// Another Delegate Payload under the same signature. All payloads of a
    /// link must agree on whether they carry `cnf`, because the link has one
    /// `typ`. Exactly one of them is disclosed at presentation.
    pub fn add_payload(mut self, payload: SdPayload) -> Self {
        self.payloads.push(payload);
        self
    }

    pub fn binding(mut self, binding: HashBinding) -> Self {
        self.binding = binding;
        self
    }

    pub fn header(mut self, name: &str, value: Value) -> Self {
        self.header.insert(name.to_owned(), value);
        self
    }

    pub fn sd_alg(mut self, alg: SdAlg) -> Self {
        self.sd_alg = alg;
        self
    }

    pub(crate) fn sign<S: Signer + ?Sized>(
        self,
        previous: &SdJwt,
        claims: &BindingClaims,
        signer: &S,
    ) -> Result<SdJwt, Error> {
        let with_cnf = self
            .payloads
            .iter()
            .filter(|p| p.claims().contains_key("cnf"))
            .count();
        let typ = match with_cnf {
            0 => typ::KB_SD_JWT,
            n if n == self.payloads.len() => typ::KB_SD_JWT_KB,
            _ => {
                return Err(ErrorKind::Issuance(
                    "all Delegate Payloads of a link must agree on carrying cnf",
                )
                .into())
            }
        };

        let mut disclosures = Vec::new();
        let mut digests = Vec::new();
        for payload in self.payloads {
            let (object, inner) = payload.build(self.sd_alg)?;
            // The Delegate Payload is itself an array-element disclosure
            // (draft-gco-oauth-delegate-sd-jwt, "Delegate Payload Disclosure").
            let wrapper = Disclosure::new_element(Value::Object(object));
            digests.push(wrapper.digest(self.sd_alg));
            disclosures.push(wrapper);
            disclosures.extend(inner);
        }
        digests.sort();

        let prev_alg = previous.sd_alg()?;
        let (binding_name, binding_value) = match self.binding {
            HashBinding::SdHash => ("sd_hash", prev_alg.digest(&previous.serialize())),
            HashBinding::IssuerJwtHash => ("issuer_jwt_hash", prev_alg.digest(previous.jwt())),
        };
        let mut payload = Object::new();
        payload.insert("iat".into(), claims.issued_at.into());
        payload.insert("aud".into(), claims.audience.clone().into());
        payload.insert("nonce".into(), claims.nonce.clone().into());
        payload.insert(binding_name.into(), binding_value.into());
        payload.insert("_sd_alg".into(), self.sd_alg.name().into());
        payload.insert(
            "delegate_payload".into(),
            Value::Array(digests.into_iter().map(|d| json!({ "...": d })).collect()),
        );
        let jwt = jws::sign(typ, &self.header, &payload, signer)?;
        Ok(SdJwt {
            jws: Jws::parse(&jwt)?,
            disclosures,
        })
    }
}
