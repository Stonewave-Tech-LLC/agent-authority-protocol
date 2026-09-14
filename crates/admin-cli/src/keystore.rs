//! Local storage for Neo's principal Ed25519 seed. The seed never leaves
//! this file, and this file never leaves this machine (nothing in this
//! crate ever POSTs it anywhere) — only the derived PUBLIC key and JWS
//! signatures produced from it are ever sent to the server. Encrypted at
//! rest with a passphrase (Argon2id -> AES-256-GCM) so a stolen laptop
//! disk image alone isn't enough to extract it.

use std::fs;
use std::path::PathBuf;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::Argon2;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct EncryptedKeyFile {
    salt: String,
    nonce: String,
    ciphertext: String,
}

pub fn admin_dir() -> PathBuf {
    dirs::home_dir()
        .expect("could not determine home directory")
        .join(".aap-admin")
}

fn key_file_path() -> PathBuf {
    admin_dir().join("principal.key.enc")
}

pub fn key_exists() -> bool {
    key_file_path().exists()
}

fn derive_aes_key(passphrase: &str, salt: &[u8; 16]) -> [u8; 32] {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .expect("argon2 key derivation failed");
    key
}

/// Generates a fresh Ed25519 seed, encrypts it with the given passphrase,
/// and writes it to ~/.aap-admin/principal.key.enc (0600). Refuses to
/// overwrite an existing file — callers must remove it explicitly first
/// (deliberately no "force" flag here: this file is the only copy of a key
/// that, once rotated, invalidates every already-paired device).
pub fn generate_and_store(passphrase: &str) -> [u8; 32] {
    let path = key_file_path();
    if path.exists() {
        panic!("{} already exists — refusing to overwrite. Remove it manually first if you really intend to generate a new principal key (this will require every paired device to re-pair).", path.display());
    }

    let mut seed = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);

    store(&seed, passphrase);
    seed
}

fn store(seed: &[u8; 32], passphrase: &str) {
    let mut salt = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut salt);
    let aes_key = derive_aes_key(passphrase, &salt);

    let mut nonce_bytes = [0u8; 12];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce_bytes);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&aes_key));
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), seed.as_slice())
        .expect("AES-GCM encryption failed");

    let envelope = EncryptedKeyFile {
        salt: B64.encode(salt),
        nonce: B64.encode(nonce_bytes),
        ciphertext: B64.encode(ciphertext),
    };

    let dir = admin_dir();
    fs::create_dir_all(&dir).expect("could not create ~/.aap-admin");
    let path = key_file_path();
    fs::write(&path, serde_json::to_string_pretty(&envelope).unwrap())
        .expect("could not write key file");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("could not chmod key file");
    }
}

/// Decrypts and returns the seed. Wrong passphrase -> Err, never panics
/// (this is the path a human mistypes something on, not a programming error).
pub fn load(passphrase: &str) -> Result<[u8; 32], String> {
    let path = key_file_path();
    let raw =
        fs::read_to_string(&path).map_err(|e| format!("could not read {}: {e}", path.display()))?;
    let envelope: EncryptedKeyFile =
        serde_json::from_str(&raw).map_err(|e| format!("corrupt key file: {e}"))?;

    let salt: [u8; 16] = B64
        .decode(&envelope.salt)
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| "corrupt key file: salt wrong length".to_string())?;
    let nonce = B64.decode(&envelope.nonce).map_err(|e| e.to_string())?;
    let ciphertext = B64
        .decode(&envelope.ciphertext)
        .map_err(|e| e.to_string())?;

    let aes_key = derive_aes_key(passphrase, &salt);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&aes_key));
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&nonce), ciphertext.as_slice())
        .map_err(|_| "wrong passphrase (or corrupt key file)".to_string())?;

    plaintext
        .try_into()
        .map_err(|_| "corrupt key file: decrypted seed has the wrong length".to_string())
}
