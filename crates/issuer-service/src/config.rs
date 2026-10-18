//! Environment-based configuration. The binary is identical for staging and
//! production; everything that differs is read from here, and anything
//! unrecognised or contradictory stops the process before it listens.

use std::net::SocketAddr;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Env {
    Staging,
    Production,
}

impl Env {
    pub fn as_str(self) -> &'static str {
        match self {
            Env::Staging => "staging",
            Env::Production => "production",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("{0} must be set")]
    Missing(&'static str),
    #[error("{0} has an invalid value")]
    Invalid(&'static str),
    #[error("ISSUER_ALLOW_DEVELOPMENT_AAGUID=true is not allowed when ISSUER_ENV=production")]
    DevelopmentInProduction,
}

#[derive(Debug, Clone)]
pub struct RateLimits {
    /// Requests per minute per client IP.
    pub challenge_per_min: u32,
    pub enrollment_per_min: u32,
    pub assertion_per_min: u32,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub env: Env,
    pub bind: SocketAddr,
    pub database_url: String,
    /// Allowed `TEAMID.bundleId` values for App Attest.
    pub app_ids: Vec<String>,
    /// Accept the App Attest `development` aaguid. Staging only.
    pub allow_development: bool,
    /// Header carrying the client IP when behind a trusted reverse proxy
    /// (the rightmost entry is used). Unset means: use the socket peer.
    pub client_ip_header: Option<String>,
    pub challenge_ttl: Duration,
    pub rate_limits: RateLimits,
}

fn parse_bool(name: &'static str, v: Option<String>) -> Result<bool, ConfigError> {
    match v.as_deref() {
        None | Some("false") => Ok(false),
        Some("true") => Ok(true),
        Some(_) => Err(ConfigError::Invalid(name)),
    }
}

fn valid_app_id(id: &str) -> bool {
    match id.split_once('.') {
        Some((team, bundle)) => {
            team.len() == 10
                && team
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
                && !bundle.is_empty()
                && bundle.len() <= 155
                && bundle
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        }
        None => false,
    }
}

fn parse_u32(name: &'static str, v: Option<String>, default: u32) -> Result<u32, ConfigError> {
    match v {
        None => Ok(default),
        Some(s) => match s.parse::<u32>() {
            Ok(n) if n > 0 => Ok(n),
            _ => Err(ConfigError::Invalid(name)),
        },
    }
}

impl Config {
    /// Reads the process environment.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// Testable core: `get` stands in for the environment.
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let env = match get("ISSUER_ENV").as_deref() {
            Some("staging") => Env::Staging,
            Some("production") => Env::Production,
            Some(_) => return Err(ConfigError::Invalid("ISSUER_ENV")),
            None => return Err(ConfigError::Missing("ISSUER_ENV")),
        };
        let allow_development = parse_bool(
            "ISSUER_ALLOW_DEVELOPMENT_AAGUID",
            get("ISSUER_ALLOW_DEVELOPMENT_AAGUID"),
        )?;
        if env == Env::Production && allow_development {
            return Err(ConfigError::DevelopmentInProduction);
        }
        let database_url =
            get("ISSUER_DATABASE_URL").ok_or(ConfigError::Missing("ISSUER_DATABASE_URL"))?;
        let app_ids: Vec<String> = get("ISSUER_APP_IDS")
            .ok_or(ConfigError::Missing("ISSUER_APP_IDS"))?
            .split(',')
            .map(|s| s.trim().to_string())
            .collect();
        if app_ids.is_empty() || !app_ids.iter().all(|id| valid_app_id(id)) {
            return Err(ConfigError::Invalid("ISSUER_APP_IDS"));
        }
        let bind: SocketAddr = get("ISSUER_BIND")
            .unwrap_or_else(|| "127.0.0.1:3010".to_string())
            .parse()
            .map_err(|_| ConfigError::Invalid("ISSUER_BIND"))?;
        let client_ip_header = get("ISSUER_CLIENT_IP_HEADER").map(|h| h.to_ascii_lowercase());
        if let Some(h) = &client_ip_header {
            if h.is_empty() || !h.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
                return Err(ConfigError::Invalid("ISSUER_CLIENT_IP_HEADER"));
            }
        }
        Ok(Config {
            env,
            bind,
            database_url,
            app_ids,
            allow_development,
            client_ip_header,
            challenge_ttl: Duration::from_secs(300),
            rate_limits: RateLimits {
                challenge_per_min: parse_u32(
                    "ISSUER_RATE_CHALLENGE_PER_MIN",
                    get("ISSUER_RATE_CHALLENGE_PER_MIN"),
                    20,
                )?,
                enrollment_per_min: parse_u32(
                    "ISSUER_RATE_ENROLLMENT_PER_MIN",
                    get("ISSUER_RATE_ENROLLMENT_PER_MIN"),
                    10,
                )?,
                assertion_per_min: parse_u32(
                    "ISSUER_RATE_ASSERTION_PER_MIN",
                    get("ISSUER_RATE_ASSERTION_PER_MIN"),
                    120,
                )?,
            },
        })
    }
}

/// Settings for the `migrate` subcommand only; the server never sees them.
#[derive(Debug, Clone)]
pub struct MigrateConfig {
    pub database_url: String,
    pub app_role: String,
}

pub fn valid_role_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && name.as_bytes()[0].is_ascii_lowercase()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

impl MigrateConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        let database_url = std::env::var("ISSUER_MIGRATE_DATABASE_URL")
            .map_err(|_| ConfigError::Missing("ISSUER_MIGRATE_DATABASE_URL"))?;
        let app_role =
            std::env::var("ISSUER_APP_ROLE").unwrap_or_else(|_| "aap_issuer_app".to_string());
        if !valid_role_name(&app_role) {
            return Err(ConfigError::Invalid("ISSUER_APP_ROLE"));
        }
        Ok(MigrateConfig {
            database_url,
            app_role,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn base() -> HashMap<&'static str, &'static str> {
        HashMap::from([
            ("ISSUER_ENV", "staging"),
            ("ISSUER_DATABASE_URL", "postgres://u@127.0.0.1/db"),
            ("ISSUER_APP_IDS", "ABCDE12345.com.example.issuer"),
        ])
    }

    fn load(m: &HashMap<&'static str, &'static str>) -> Result<Config, ConfigError> {
        Config::from_lookup(|k| m.get(k).map(|v| v.to_string()))
    }

    #[test]
    fn defaults_bind_to_loopback_and_reject_development() {
        let c = load(&base()).unwrap();
        assert!(c.bind.ip().is_loopback());
        assert!(!c.allow_development);
        assert_eq!(c.env, Env::Staging);
    }

    #[test]
    fn production_with_development_aaguid_refuses_to_start() {
        let mut m = base();
        m.insert("ISSUER_ENV", "production");
        m.insert("ISSUER_ALLOW_DEVELOPMENT_AAGUID", "true");
        assert_eq!(load(&m).err(), Some(ConfigError::DevelopmentInProduction));
    }

    #[test]
    fn staging_may_accept_development_aaguid() {
        let mut m = base();
        m.insert("ISSUER_ALLOW_DEVELOPMENT_AAGUID", "true");
        assert!(load(&m).unwrap().allow_development);
    }

    #[test]
    fn production_without_development_flag_is_fine() {
        let mut m = base();
        m.insert("ISSUER_ENV", "production");
        assert_eq!(load(&m).unwrap().env, Env::Production);
    }

    #[test]
    fn env_must_be_explicit_and_known() {
        let mut m = base();
        m.remove("ISSUER_ENV");
        assert_eq!(load(&m).err(), Some(ConfigError::Missing("ISSUER_ENV")));
        m.insert("ISSUER_ENV", "prod");
        assert_eq!(load(&m).err(), Some(ConfigError::Invalid("ISSUER_ENV")));
    }

    #[test]
    fn booleans_and_app_ids_are_strict() {
        let mut m = base();
        m.insert("ISSUER_ALLOW_DEVELOPMENT_AAGUID", "1");
        assert!(load(&m).is_err());
        let mut m = base();
        m.insert("ISSUER_APP_IDS", "lowercase.com.example");
        assert!(load(&m).is_err());
        m.insert("ISSUER_APP_IDS", "ABCDE12345.com.example,");
        assert!(load(&m).is_err());
    }

    #[test]
    fn role_names_are_restricted() {
        assert!(valid_role_name("aap_issuer_app"));
        assert!(!valid_role_name("Aap"));
        assert!(!valid_role_name("a;drop"));
        assert!(!valid_role_name(""));
    }
}
