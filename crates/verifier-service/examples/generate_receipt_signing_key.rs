//! Generates a fresh Ed25519 seed for AAP_VERIFIER_RECEIPT_SIGNING_KEY.
//! Run once per verifier-service deployment, store the output as a secret
//! (Infisical), never print/log it after initial setup.

use aap_core::{LocalSigner, Signer};
use base64::Engine as _;

fn main() {
    let signer = LocalSigner::generate();
    let seed = signer
        .to_ed25519_bytes()
        .expect("generate() always produces an Ed25519 key");
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(seed);
    println!("AAP_VERIFIER_RECEIPT_SIGNING_KEY={encoded}");
    eprintln!(
        "public key (for reference, not secret): {:?}",
        signer.public_jwk()
    );
}
