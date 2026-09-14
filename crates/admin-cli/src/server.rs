//! Thin HTTP client for the stonewave-systems endpoints this CLI talks to.
//! Auth is the same `x-agent-key` full-scope account key any other trusted
//! local tool uses (minted once via the existing /agent-keys UI) — no new
//! auth mechanism invented here.

use aap_core::PublicKeyJwk;
use serde::{Deserialize, Serialize};

pub struct Client {
    base_url: String,
    agent_key: String,
    http: reqwest::blocking::Client,
}

#[derive(Deserialize)]
pub struct PrincipalInfo {
    pub principal_id: String,
    #[allow(dead_code)]
    pub public_key: PublicKeyJwk,
}

#[derive(Deserialize)]
struct GetPrincipalResponse {
    principal: Option<PrincipalInfo>,
}

#[derive(Serialize)]
struct RegisterPrincipalRequest<'a> {
    public_key: &'a PublicKeyJwk,
}

#[derive(Deserialize)]
pub struct RegisterPrincipalResponse {
    pub principal_id: String,
}

#[derive(Deserialize, Debug)]
pub struct PairingRequest {
    pub id: String,
    pub requested_agent_id: String,
    pub device_label: String,
    pub public_key: PublicKeyJwk,
    #[allow(dead_code)]
    pub requested_scope: serde_json::Value,
    pub status: String,
    pub created_at: String,
    pub expires_at: String,
}

#[derive(Deserialize)]
struct ListPairingResponse {
    pairing_requests: Vec<PairingRequest>,
}

#[derive(Serialize)]
struct FinalizeRequest<'a> {
    delegation_jws: &'a str,
}

#[derive(Deserialize)]
pub struct FinalizeResponse {
    pub delegation_id: String,
}

#[derive(Deserialize)]
struct ApiError {
    error: String,
}

impl Client {
    pub fn from_env() -> Self {
        let base_url = std::env::var("AAP_ADMIN_SERVER_URL")
            .unwrap_or_else(|_| "https://systems.stonewavetech.com".to_string());
        let agent_key = std::env::var("AAP_ADMIN_AGENT_KEY").unwrap_or_else(|_| {
            eprintln!(
                "AAP_ADMIN_AGENT_KEY is not set. Mint a full-scope account key once via the \
                 /agent-keys page in stonewave-systems, then export it, e.g.:\n\n  \
                 export AAP_ADMIN_AGENT_KEY=swk_...\n"
            );
            std::process::exit(1);
        });
        Self {
            base_url,
            agent_key,
            http: reqwest::blocking::Client::new(),
        }
    }

    fn error_from_body(status: reqwest::StatusCode, body: &str) -> String {
        match serde_json::from_str::<ApiError>(body) {
            Ok(e) => format!("HTTP {status}: {}", e.error),
            Err(_) => format!("HTTP {status}: {body}"),
        }
    }

    pub fn get_my_principal(&self) -> Result<Option<PrincipalInfo>, String> {
        let res = self
            .http
            .get(format!("{}/api/aap/principals", self.base_url))
            .header("x-agent-key", &self.agent_key)
            .send()
            .map_err(|e| e.to_string())?;
        let status = res.status();
        let body = res.text().map_err(|e| e.to_string())?;
        if !status.is_success() {
            return Err(Self::error_from_body(status, &body));
        }
        let parsed: GetPrincipalResponse =
            serde_json::from_str(&body).map_err(|e| e.to_string())?;
        Ok(parsed.principal)
    }

    pub fn register_principal(
        &self,
        public_key: &PublicKeyJwk,
    ) -> Result<RegisterPrincipalResponse, String> {
        let res = self
            .http
            .post(format!("{}/api/aap/principals", self.base_url))
            .header("x-agent-key", &self.agent_key)
            .json(&RegisterPrincipalRequest { public_key })
            .send()
            .map_err(|e| e.to_string())?;
        let status = res.status();
        let body = res.text().map_err(|e| e.to_string())?;
        if !status.is_success() {
            return Err(Self::error_from_body(status, &body));
        }
        serde_json::from_str(&body).map_err(|e| e.to_string())
    }

    pub fn list_pairing_requests(&self) -> Result<Vec<PairingRequest>, String> {
        let res = self
            .http
            .get(format!(
                "{}/api/aap/devices/pairing-requests",
                self.base_url
            ))
            .header("x-agent-key", &self.agent_key)
            .send()
            .map_err(|e| e.to_string())?;
        let status = res.status();
        let body = res.text().map_err(|e| e.to_string())?;
        if !status.is_success() {
            return Err(Self::error_from_body(status, &body));
        }
        let parsed: ListPairingResponse = serde_json::from_str(&body).map_err(|e| e.to_string())?;
        Ok(parsed.pairing_requests)
    }

    pub fn finalize_pairing(
        &self,
        id: &str,
        delegation_jws: &str,
    ) -> Result<FinalizeResponse, String> {
        let res = self
            .http
            .post(format!(
                "{}/api/aap/devices/pairing-requests/{id}/finalize",
                self.base_url
            ))
            .header("x-agent-key", &self.agent_key)
            .json(&FinalizeRequest { delegation_jws })
            .send()
            .map_err(|e| e.to_string())?;
        let status = res.status();
        let body = res.text().map_err(|e| e.to_string())?;
        if !status.is_success() {
            return Err(Self::error_from_body(status, &body));
        }
        serde_json::from_str(&body).map_err(|e| e.to_string())
    }
}
