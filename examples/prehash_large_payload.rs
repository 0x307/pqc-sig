//! Pre-hash signing example — `sign_prehash`/`sign_prehash_deterministic`/
//! `verify_prehash` (S-4).
//!
//! Demonstrates the intended use case: hashing a large payload (a multi-MB "module")
//! once with an approved hash function, then signing only the digest with ML-DSA-65.
//! Also demonstrates the built-in guardrails: a tampered digest fails verification, a
//! digest of the wrong length is rejected, and a hash function too weak for the
//! parameter set's security strength is rejected.
//!
//! Run with:
//! ```sh
//! cargo run --example prehash_large_payload
//! ```

use pqc_sig::fips204::MlDsa65Keypair;
use pqc_sig::prehash::PreHash;
use pqc_sig::SigError;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256, Sha512};

const MODULE_CTX: &[u8] = b"8gentz-module-v1";

fn main() {
    let keypair = MlDsa65Keypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();

    // A stand-in for a large WASM module / log bundle / firmware image: several MB,
    // built without ever holding two copies of it in memory at once.
    let module_bytes: Vec<u8> = (0..8usize)
        .flat_map(|i| core::iter::repeat_n(i as u8, 1_000_000))
        .collect();
    println!("module size:        {} bytes", module_bytes.len());

    // The host hashes the module once with SHA-512 (256-bit collision strength —
    // sufficient for ML-DSA-65's 192-bit requirement).
    let digest = Sha512::digest(&module_bytes);
    println!("digest (SHA-512):    {} bytes", digest.len());

    // Sign only the digest, deterministically, under a module-integrity context.
    let sig = keypair
        .sign_prehash_deterministic(MODULE_CTX, PreHash::Sha512, &digest)
        .expect("sign_prehash_deterministic failed");
    println!("signature:           {} bytes", sig.bytes.len());

    // Verify against the same digest.
    MlDsa65Keypair::verify_prehash(&pk, MODULE_CTX, PreHash::Sha512, &digest, &sig)
        .expect("verify_prehash must succeed for the correct digest");
    println!("[ok]   verify_prehash succeeds for the correct digest");

    // A tampered digest (e.g. a corrupted or substituted module) must be rejected.
    let mut tampered_digest = digest.to_vec();
    tampered_digest[0] ^= 0xFF;
    let result =
        MlDsa65Keypair::verify_prehash(&pk, MODULE_CTX, PreHash::Sha512, &tampered_digest, &sig);
    assert!(result.is_err(), "tampered digest must be rejected");
    println!(
        "[ok]   tampered digest is REJECTED: {:?}",
        result.unwrap_err()
    );

    // A pre-hash signature does NOT verify via the plain (pure-mode) API, and vice
    // versa — the leading 0x01 domain byte structurally separates the two modes.
    let result = MlDsa65Keypair::verify_ctx(&pk, MODULE_CTX, &digest, &sig);
    assert!(
        result.is_err(),
        "a HashML-DSA signature must NOT verify via plain verify_ctx() over the digest bytes"
    );
    println!(
        "[ok]   sign_prehash signature is REJECTED by verify_ctx() (domain separation): {:?}",
        result.unwrap_err()
    );

    // SHA-256 (128-bit collision strength) is too weak for ML-DSA-65 (192-bit
    // requirement) — this is rejected before any signing/verification is attempted.
    let weak_digest = Sha256::digest(&module_bytes);
    let result = keypair.sign_prehash_deterministic(MODULE_CTX, PreHash::Sha256, &weak_digest);
    match result {
        Err(SigError::PreHashTooWeak { hash, strength, algorithm, required }) => {
            println!(
                "[ok]   PreHash::Sha256 REJECTED for ML-DSA-65: hash={hash} strength={strength} \
                 algorithm={algorithm} required={required}"
            );
        }
        other => panic!("expected PreHashTooWeak, got {other:?}"),
    }

    // A digest of the wrong length for the chosen PreHash is rejected too.
    let short_digest = &digest[..digest.len() - 1]; // 63 bytes, SHA-512 wants 64
    let result = keypair.sign_prehash_deterministic(MODULE_CTX, PreHash::Sha512, short_digest);
    match result {
        Err(SigError::InvalidDigestLength { hash, expected, got }) => {
            println!(
                "[ok]   wrong-length digest REJECTED: hash={hash} expected={expected} got={got}"
            );
        }
        other => panic!("expected InvalidDigestLength, got {other:?}"),
    }

    println!("\nPre-hash signing demo completed successfully.");
}
