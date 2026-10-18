mod keystore;
mod server;

use std::fs::{self, OpenOptions};
use std::io::{BufRead as _, BufReader, Write as _};
use std::path::PathBuf;

use aap_core::{delegation, DelegationParams, LocalSigner, PrincipalType, Scope};
use chrono::Duration;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "aap-admin",
    about = "Principal-side tooling: holds Neo's AAP principal key locally, signs device Delegations.",
    long_about = "Principal-side tooling: holds Neo's AAP principal key locally, signs device Delegations.

                  Assurance level AL0: the key is a software key on the same machine your agents run on.                   Use it for development and automation only, never for delegations that carry real liability."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Manage the local principal key.
    Key {
        #[command(subcommand)]
        action: KeyAction,
    },
    /// Manage device pairing requests.
    Pairing {
        #[command(subcommand)]
        action: PairingAction,
    },
}

#[derive(Subcommand)]
enum KeyAction {
    /// Generate a principal key if none exists locally yet, and make sure the server has its public key registered. Safe to re-run — never overwrites an existing key.
    Init,
}

#[derive(Subcommand)]
enum PairingAction {
    /// List open (pending, not yet expired) device pairing requests.
    List,
    /// Sign a Delegation locally for a pending pairing request (does not submit it — review the printed summary, then run `pairing finalize`).
    Sign { id: String },
    /// Submit a previously signed Delegation (see `pairing sign`) to the server, completing the pairing.
    Finalize { id: String },
}

/// Reads a passphrase from the terminal without echoing it. There is
/// deliberately no environment-variable shortcut: any process running as
/// the user — including a coding agent with shell access — can read the
/// environment, and a passphrase sitting there unlocks the principal key
/// for whoever finds it.
fn get_passphrase(prompt: &str) -> String {
    rpassword::prompt_password(prompt).expect("failed to read passphrase")
}

/// Asks a yes/no question on the terminal device itself, not on stdin.
/// stdin is whatever the caller pipes in: `echo y | aap-admin pairing sign`
/// would let any process approve a delegation on the user's behalf. Reading
/// the terminal raises that bar but does not remove it — a process can
/// still drive a pseudo-terminal — which is why this CLI is AL0 only.
fn confirm_on_terminal(prompt: &str) -> bool {
    #[cfg(windows)]
    let (input_path, output_path) = ("CONIN$", "CONOUT$");
    #[cfg(not(windows))]
    let (input_path, output_path) = ("/dev/tty", "/dev/tty");

    let no_terminal = "no interactive terminal available — refusing to sign without a confirmation typed by a human";
    let mut output = OpenOptions::new()
        .write(true)
        .open(output_path)
        .expect(no_terminal);
    let input = OpenOptions::new()
        .read(true)
        .write(true)
        .open(input_path)
        .expect(no_terminal);

    write!(output, "{prompt}").ok();
    output.flush().ok();
    let mut answer = String::new();
    BufReader::new(input)
        .read_line(&mut answer)
        .expect("failed to read confirmation from the terminal");
    answer.trim().eq_ignore_ascii_case("y")
}

/// Human-readable lines for a Scope, rendered locally from the parsed
/// structure. The server's raw JSON is never shown as the thing being
/// approved: whoever controls the server would control what the user reads.
fn render_scope(scope: &Scope) -> Vec<String> {
    let mut lines = vec![format!("actions:          {}", scope.actions.join(", "))];
    lines.push(match &scope.resources {
        Some(r) => format!("resources:        {}", r.join(", ")),
        None => "resources:        ANY resource".to_string(),
    });
    lines.push(match &scope.max_amount {
        Some(a) => format!("max amount:       {:.2} {} per action", a.value, a.currency),
        None => "max amount:       none (requests carrying an amount are denied)".to_string(),
    });
    if let Some(cps) = &scope.counterparties {
        if let Some(allow) = &cps.allow {
            lines.push(format!("counterparties:   only {}", allow.join(", ")));
        }
        if let Some(deny) = &cps.deny {
            lines.push(format!("never with:       {}", deny.join(", ")));
        }
    }
    if let Some(dc) = &scope.data_categories {
        lines.push(format!("data categories:  {}", dc.join(", ")));
    }
    match &scope.time_windows {
        Some(windows) => {
            for w in windows {
                let days: Vec<String> = w
                    .days
                    .iter()
                    .map(|d| format!("{d:?}").to_lowercase())
                    .collect();
                lines.push(format!(
                    "time window:      {} {}–{} ({})",
                    days.join(","),
                    w.start,
                    w.end,
                    w.timezone
                ));
            }
        }
        None => lines.push("time window:      any time".to_string()),
    }
    lines
}

fn pending_delegation_path(id: &str) -> PathBuf {
    keystore::admin_dir()
        .join("pending-delegations")
        .join(format!("{id}.jws"))
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Command::Key {
            action: KeyAction::Init,
        } => cmd_key_init(),
        Command::Pairing {
            action: PairingAction::List,
        } => cmd_pairing_list(),
        Command::Pairing {
            action: PairingAction::Sign { id },
        } => cmd_pairing_sign(&id),
        Command::Pairing {
            action: PairingAction::Finalize { id },
        } => cmd_pairing_finalize(&id),
    }
}

fn cmd_key_init() {
    let client = server::Client::from_env();

    if !keystore::key_exists() {
        println!("No local principal key found — generating one now.");
        println!(
            "This key signs every device Delegation you ever issue. It never leaves this machine."
        );
        let passphrase = get_passphrase("Choose a passphrase to encrypt it at rest: ");
        let confirm = get_passphrase("Confirm passphrase: ");
        if passphrase != confirm {
            eprintln!("Passphrases did not match — aborting, no key was written.");
            std::process::exit(1);
        }
        keystore::generate_and_store(&passphrase);
        println!(
            "Local key written to {}",
            keystore::admin_dir().join("principal.key.enc").display()
        );
    } else {
        println!(
            "Local principal key already exists at {} — not touching it.",
            keystore::admin_dir().join("principal.key.enc").display()
        );
    }

    match client.get_my_principal() {
        Ok(Some(info)) => {
            println!(
                "Server already has a principal registered: {}",
                info.principal_id
            );
            println!("If this doesn't match your local key (e.g. you're on a new machine), you need a real key-rotation flow — not implemented yet, ask Ace.");
        }
        Ok(None) => {
            println!("No principal registered on the server yet — registering now.");
            let passphrase = get_passphrase("Passphrase to unlock the local key: ");
            let seed = match keystore::load(&passphrase) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Could not unlock local key: {e}");
                    std::process::exit(1);
                }
            };
            let signer = LocalSigner::from_ed25519_bytes(&seed);
            let public_jwk = aap_core::Signer::public_jwk(&signer);
            match client.register_principal(&public_jwk) {
                Ok(res) => println!(
                    "Registered with the server as principal_id: {}",
                    res.principal_id
                ),
                Err(e) => {
                    eprintln!("Registration failed: {e}");
                    std::process::exit(1);
                }
            }
        }
        Err(e) => {
            eprintln!("Could not check server registration status: {e}");
            std::process::exit(1);
        }
    }
}

fn cmd_pairing_list() {
    let client = server::Client::from_env();
    match client.list_pairing_requests() {
        Ok(requests) if requests.is_empty() => println!("No open pairing requests."),
        Ok(requests) => {
            for r in requests {
                println!(
                    "{}  agent_id={}  label=\"{}\"  status={}  created_at={}  expires_at={}",
                    r.id,
                    r.requested_agent_id,
                    r.device_label,
                    r.status,
                    r.created_at,
                    r.expires_at
                );
            }
        }
        Err(e) => {
            eprintln!("Failed to list pairing requests: {e}");
            std::process::exit(1);
        }
    }
}

fn cmd_pairing_sign(id: &str) {
    let client = server::Client::from_env();
    let requests = match client.list_pairing_requests() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Failed to fetch pairing requests: {e}");
            std::process::exit(1);
        }
    };
    let Some(request) = requests.into_iter().find(|r| r.id == id) else {
        eprintln!("No open pairing request with id {id} (already fulfilled/expired, or a typo).");
        std::process::exit(1);
    };

    let scope: Scope =
        serde_json::from_value(request.requested_scope.clone()).unwrap_or_else(|e| {
            eprintln!("Requested scope is not a valid Scope object: {e}");
            std::process::exit(1);
        });

    println!("Pairing request {}:", request.id);
    println!("  device:           {}", request.device_label);
    println!("  agent_id:         {}", request.requested_agent_id);
    println!(
        "  device key:       {} {} x={}",
        request.public_key.kty, request.public_key.crv, request.public_key.x
    );
    println!("  valid for:        365 days");
    println!("  may sub-delegate: no");
    for line in render_scope(&scope) {
        println!("  {line}");
    }
    println!();
    if !confirm_on_terminal(
        "Sign a Delegation for this device with exactly these parameters? [y/N] ",
    ) {
        println!("Aborted — nothing signed.");
        return;
    }

    let passphrase = get_passphrase("Passphrase to unlock the local principal key: ");
    let seed = match keystore::load(&passphrase) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Could not unlock local key: {e}");
            std::process::exit(1);
        }
    };
    let principal_signer = LocalSigner::from_ed25519_bytes(&seed);

    let client_for_principal = server::Client::from_env();
    let principal_id = match client_for_principal.get_my_principal() {
        Ok(Some(info)) => info.principal_id,
        Ok(None) => {
            eprintln!("No principal registered on the server — run `aap-admin key init` first.");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Could not look up principal_id: {e}");
            std::process::exit(1);
        }
    };

    let issued = delegation::issue(
        &principal_signer,
        DelegationParams {
            principal_id: principal_id.clone(),
            principal_type: PrincipalType::NaturalPerson,
            agent_id: request.requested_agent_id.clone(),
            agent_public_key: request.public_key,
            scope,
            valid_for: Duration::days(365),
            status_endpoint: format!(
                "https://systems.stonewavetech.com/api/aap/devices/{}/status",
                request.requested_agent_id
            ),
            can_delegate: false,
            max_delegation_depth: None,
            parent_delegation_id: None,
            metadata: None,
        },
    )
    .unwrap_or_else(|e| {
        eprintln!("Signing failed: {e}");
        std::process::exit(1);
    });

    let path = pending_delegation_path(id);
    fs::create_dir_all(path.parent().unwrap()).expect("could not create pending-delegations dir");
    fs::write(&path, &issued.jws).expect("could not write signed delegation");

    println!();
    println!(
        "Signed. Delegation valid until {}.",
        issued.payload.valid_until
    );
    println!("Saved to {} — review it, then run:", path.display());
    println!("  aap-admin pairing finalize {id}");
}

fn cmd_pairing_finalize(id: &str) {
    let path = pending_delegation_path(id);
    let jws = match fs::read_to_string(&path) {
        Ok(j) => j,
        Err(_) => {
            eprintln!("No signed delegation found for {id} at {} — run `aap-admin pairing sign {id}` first.", path.display());
            std::process::exit(1);
        }
    };

    let client = server::Client::from_env();
    match client.finalize_pairing(id, &jws) {
        Ok(res) => {
            println!("Pairing finalized. delegation_id: {}", res.delegation_id);
            fs::remove_file(&path).ok();
        }
        Err(e) => {
            eprintln!("Finalize failed: {e}");
            eprintln!(
                "The signed delegation is still saved at {} — fix the issue and retry.",
                path.display()
            );
            std::process::exit(1);
        }
    }
}
