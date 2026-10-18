//! A whole presentation in compact serialization. One type covers all four
//! shapes, because each is the previous one plus one more element:
//!
//! ```text
//! SD-JWT        <JWT>~<D>~...~<D>~
//! SD-JWT+KB     <JWT>~<D>~...~<D>~<KB-JWT>
//! dSD-JWT       <JWT>~<D>~...~<D>~~<KB-SD-JWT>~<D>~...~<D>~   (one or more links)
//! dSD-JWT+KB    <JWT>~<D>~...~<D>~~<KB-SD-JWT>~<D>~...~<D>~<KB-JWT>
//! ```
//!
//! Splitting rule (draft-gco-oauth-delegate-sd-jwt, Compact Serialization):
//! split on `~`; each element is a JWT followed by its disclosures; exactly
//! one empty component separates an element from the KB-SD-JWT after it; a
//! JWT that follows a disclosure (or a JWT) directly is the final KB-JWT and
//! must be the last component; a trailing empty component means no KB-JWT.
//! Anything else (`~~~`, a missing final `~`, a JWT in the middle) is
//! malformed.

use serde_json::Value;

use crate::error::{Error, ErrorKind, Position};
use crate::jws::{self, looks_like_jwt, Jws, Object};
use crate::keys::Signer;
use crate::sdjwt::{BindingClaims, LinkBuilder, SdJwt};
use crate::typ;

#[derive(Debug, Clone)]
pub struct Presentation {
    root: SdJwt,
    links: Vec<SdJwt>,
    key_binding: Option<Jws>,
}

impl Presentation {
    /// Starts a presentation from an Issuer-signed SD-JWT.
    pub fn new(root: SdJwt) -> Self {
        Presentation {
            root,
            links: Vec::new(),
            key_binding: None,
        }
    }

    pub(crate) fn parse(input: &str) -> Result<Self, ErrorKind> {
        let components: Vec<&str> = input.split('~').collect();
        if components.len() < 2 {
            return Err(ErrorKind::Malformed("missing the final ~"));
        }
        let mut elements = Vec::new();
        let mut key_binding = None;
        let mut i = 0;
        loop {
            let jwt = components[i];
            if !looks_like_jwt(jwt) {
                return Err(ErrorKind::Malformed("expected a JWT"));
            }
            i += 1;
            let mut disclosures = Vec::new();
            while i < components.len() && !components[i].is_empty() {
                let c = components[i];
                if looks_like_jwt(c) {
                    if i != components.len() - 1 {
                        return Err(ErrorKind::Malformed("a KB-JWT must be the last component"));
                    }
                    key_binding = Some(Jws::parse(c)?);
                    break;
                }
                if c.contains('.') {
                    return Err(ErrorKind::Malformed(
                        "component is neither JWT nor disclosure",
                    ));
                }
                disclosures.push(c);
                i += 1;
            }
            elements.push(SdJwt::from_parts(jwt, &disclosures)?);
            if key_binding.is_some() {
                break;
            }
            if i >= components.len() {
                return Err(ErrorKind::Malformed("missing the final ~"));
            }
            // components[i] is the empty separator / terminator.
            i += 1;
            if i == components.len() {
                break;
            }
        }
        let mut elements = elements.into_iter();
        Ok(Presentation {
            root: elements.next().expect("at least one element"),
            links: elements.collect(),
            key_binding,
        })
    }

    pub fn root(&self) -> &SdJwt {
        &self.root
    }

    /// The KB-SD-JWTs after the root, in chain order.
    pub fn links(&self) -> &[SdJwt] {
        &self.links
    }

    /// The final KB-JWT, if the presentation has one.
    pub fn key_binding_jwt(&self) -> Option<&str> {
        self.key_binding.as_ref().map(Jws::raw)
    }

    pub(crate) fn key_binding(&self) -> Option<&Jws> {
        self.key_binding.as_ref()
    }

    /// The last element: the one the next link or KB-JWT binds to.
    pub fn last(&self) -> &SdJwt {
        self.links.last().unwrap_or(&self.root)
    }

    fn element_mut(&mut self, index: usize) -> Result<&mut SdJwt, Error> {
        match index {
            0 => Ok(&mut self.root),
            n => self
                .links
                .get_mut(n - 1)
                .ok_or_else(|| ErrorKind::Issuance("no element at that index").into()),
        }
    }

    /// Reduces the disclosures of element `index` (0 is the root, `n` is
    /// link `n`) to those needed for `pointers`; see [`SdJwt::select`].
    ///
    /// Only the last element can always be reduced. An earlier element can
    /// be reduced only if the link after it binds with `issuer_jwt_hash`;
    /// otherwise that link's `sd_hash` no longer matches and verification
    /// fails, as it should.
    pub fn select(mut self, index: usize, pointers: &[&str]) -> Result<Self, Error> {
        if self.key_binding.is_some() {
            return Err(ErrorKind::Issuance("presentation is already key-bound").into());
        }
        let position = match index {
            0 => Position::Root,
            n => Position::Link(n),
        };
        let element = self.element_mut(index)?;
        *element = element
            .select(pointers)
            .map_err(|e| e.kind().clone().at(position))?;
        Ok(self)
    }

    /// Appends a KB-SD-JWT signed by `signer`, the holder of the key in the
    /// last element's `cnf`, bound to the last element as presented now.
    /// Select the last element's disclosures *before* delegating.
    pub fn delegate<S: Signer + ?Sized>(
        mut self,
        link: LinkBuilder,
        claims: &BindingClaims,
        signer: &S,
    ) -> Result<Self, Error> {
        if self.key_binding.is_some() {
            return Err(ErrorKind::Issuance("presentation is already key-bound").into());
        }
        let next = link.sign(self.last(), claims, signer)?;
        self.links.push(next);
        Ok(self)
    }

    /// Appends the final KB-JWT (`typ: kb+jwt`), signed by the holder of the
    /// last element's `cnf` key, with `sd_hash` over the last element.
    pub fn bind<S: Signer + ?Sized>(
        mut self,
        claims: &BindingClaims,
        signer: &S,
    ) -> Result<Self, Error> {
        if self.key_binding.is_some() {
            return Err(ErrorKind::Issuance("presentation is already key-bound").into());
        }
        let last = self.last();
        let sd_hash = last.sd_alg()?.digest(&last.serialize());
        let mut payload = Object::new();
        payload.insert("iat".into(), claims.issued_at.into());
        payload.insert("aud".into(), claims.audience.clone().into());
        payload.insert("nonce".into(), claims.nonce.clone().into());
        payload.insert("sd_hash".into(), Value::String(sd_hash));
        let jwt = jws::sign(typ::KB_JWT, &Object::new(), &payload, signer)?;
        self.key_binding = Some(Jws::parse(&jwt)?);
        Ok(self)
    }

    /// The compact serialization.
    pub fn serialize(&self) -> String {
        let mut out = self.root.serialize();
        for link in &self.links {
            out.push('~');
            out.push_str(&link.serialize());
        }
        if let Some(kb) = &self.key_binding {
            out.push_str(kb.raw());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine as _};

    fn jwt(tag: &str) -> String {
        format!(
            "{}.{}.c2ln",
            B64.encode(r#"{"alg":"ES256"}"#),
            B64.encode(format!(r#"{{"t":"{tag}"}}"#))
        )
    }

    fn disclosure(tag: &str) -> String {
        B64.encode(format!(r#"["salt","{tag}"]"#))
    }

    #[test]
    fn splits_every_shape_and_round_trips() {
        let (r, l1, l2, kb) = (jwt("r"), jwt("l1"), jwt("l2"), jwt("kb"));
        let (d1, d2) = (disclosure("1"), disclosure("2"));
        let shapes = [
            (format!("{r}~"), 0, false),
            (format!("{r}~{d1}~{d2}~"), 0, false),
            (format!("{r}~{kb}"), 0, true),
            (format!("{r}~{d1}~{kb}"), 0, true),
            (format!("{r}~~{l1}~"), 1, false),
            (format!("{r}~{d1}~~{l1}~{d2}~"), 1, false),
            (format!("{r}~~{l1}~{kb}"), 1, true),
            (format!("{r}~{d1}~~{l1}~~{l2}~{d2}~{kb}"), 2, true),
        ];
        for (input, links, has_kb) in shapes {
            let p = Presentation::parse(&input).unwrap();
            assert_eq!(p.links().len(), links, "{input}");
            assert_eq!(p.key_binding_jwt().is_some(), has_kb, "{input}");
            assert_eq!(p.serialize(), input);
        }
    }

    #[test]
    fn rejects_malformed_shapes() {
        let (r, l1, kb) = (jwt("r"), jwt("l1"), jwt("kb"));
        let d = disclosure("1");
        for input in [
            String::new(),
            r.clone(),
            format!("{r}~{d}"),
            format!("{r}~~~{l1}~"),
            format!("{r}~{d}~{l1}~{d}~"),
            format!("{r}~{kb}~"),
            format!("{r}~~"),
            format!("~{r}~"),
            format!("{r}~a.b~"),
        ] {
            assert!(Presentation::parse(&input).is_err(), "{input}");
        }
    }
}
