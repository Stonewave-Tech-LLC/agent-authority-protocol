//! Thin WASM bindings around aap-core, scoped exactly to the demo story
//! (issue → request → replay → revoke). Not a general SDK binding — the
//! goal here is a browser page that makes the CLI demo clickable, not a
//! JS API surface for aap-core as a whole.

use chrono::{Duration, Utc};
use wasm_bindgen::prelude::*;

use aap_core::{
    delegation, message, ActionRequest, Amount, DelegationParams, InMemoryNonceStore,
    InMemoryRegistry, InMemoryStatus, LocalSigner, PrincipalType, ReceiptOutcome, Scope, Signer,
    Verifier,
};

#[wasm_bindgen]
pub struct DemoSession {
    agent_signer: LocalSigner,
    receipt_signer: LocalSigner,
    registry: InMemoryRegistry,
    status: InMemoryStatus,
    nonces: InMemoryNonceStore,
    delegation_jws: String,
    delegation_id: String,
    scope_summary: String,
    last_message_jws: Option<String>,
}

#[wasm_bindgen]
impl DemoSession {
    #[wasm_bindgen(constructor)]
    pub fn new() -> DemoSession {
        console_error_panic_hook::set_once();

        let principal_signer = LocalSigner::generate();
        let agent_signer = LocalSigner::generate();
        let receipt_signer = LocalSigner::generate();

        let registry = InMemoryRegistry::new();
        registry.register("principal:neo", principal_signer.public_jwk());

        let del = delegation::issue(
            &principal_signer,
            DelegationParams {
                principal_id: "principal:neo".into(),
                principal_type: PrincipalType::NaturalPerson,
                agent_id: "agent:wave-1".into(),
                agent_public_key: agent_signer.public_jwk(),
                scope: Scope {
                    actions: vec!["create_payment".into()],
                    max_amount: Some(Amount {
                        value: 200.0,
                        currency: "EUR".into(),
                    }),
                    ..Default::default()
                },
                valid_for: Duration::hours(1),
                status_endpoint: "https://registry.example.org/status".into(),
                can_delegate: false,
                max_delegation_depth: None,
                parent_delegation_id: None,
                metadata: None,
            },
        )
        .expect("issuance with a freshly generated local key cannot fail");

        DemoSession {
            agent_signer,
            receipt_signer,
            registry,
            status: InMemoryStatus::new(),
            nonces: InMemoryNonceStore::new(),
            delegation_id: del.payload.delegation_id.to_string(),
            delegation_jws: del.jws,
            scope_summary: "create_payment, max 200 EUR".to_string(),
            last_message_jws: None,
        }
    }

    /// JSON: { delegation_id, principal_id, agent_id, scope_summary }
    pub fn delegation_summary(&self) -> String {
        serde_json::json!({
            "delegation_id": self.delegation_id,
            "principal_id": "principal:neo",
            "agent_id": "agent:wave-1",
            "scope_summary": self.scope_summary,
        })
        .to_string()
    }

    /// Issues and verifies a fresh signed request for `amount` EUR.
    /// JSON: { accepted, reason, receipt_id, receipt_outcome, digest }
    pub fn request(&mut self, amount: f64) -> String {
        let req = ActionRequest {
            action: "create_payment".into(),
            amount: Some(Amount {
                value: amount,
                currency: "EUR".into(),
            }),
            timestamp: Utc::now(),
            ..Default::default()
        };
        let msg = message::issue(&self.agent_signer, "agent:wave-1", "bank-api", req)
            .expect("signing with a local key cannot fail");
        self.last_message_jws = Some(msg.jws.clone());
        self.run_verification(&msg.jws)
    }

    /// Re-presents the exact same signed message from the last `request()`
    /// call — demonstrates replay protection via the nonce store.
    pub fn replay_last(&mut self) -> String {
        match self.last_message_jws.clone() {
            Some(jws) => self.run_verification(&jws),
            None => serde_json::json!({ "error": "no previous request to replay yet" }).to_string(),
        }
    }

    /// Revokes the one delegation this session issued.
    pub fn revoke(&mut self) -> String {
        let id = self
            .delegation_id
            .parse()
            .expect("delegation_id was produced by Uuid::to_string()");
        self.status.revoke(id);
        serde_json::json!({ "revoked": true, "delegation_id": self.delegation_id }).to_string()
    }

    fn run_verification(&self, msg_jws: &str) -> String {
        let verifier = Verifier::new(
            "verifier:bank-api",
            "bank-api",
            &self.registry,
            &self.status,
            &self.nonces,
            &self.receipt_signer,
        );
        let outcome = verifier.verify(&[&self.delegation_jws], msg_jws);

        let (accepted, reason) = match &outcome.decision {
            Ok(_) => (true, None),
            Err(e) => (false, Some(e.to_string())),
        };
        let receipt_outcome = match &outcome.receipt.payload.outcome {
            ReceiptOutcome::Accepted => "accepted".to_string(),
            ReceiptOutcome::Rejected { reason } => reason.clone(),
        };

        serde_json::json!({
            "accepted": accepted,
            "reason": reason,
            "receipt_id": outcome.receipt.payload.receipt_id.to_string(),
            "receipt_outcome": receipt_outcome,
            "digest": outcome.receipt.payload.request_digest,
        })
        .to_string()
    }
}

impl Default for DemoSession {
    fn default() -> Self {
        Self::new()
    }
}
