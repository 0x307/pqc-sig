//! Hybrid bridge example — migrating an existing classical (Ed25519) identity into the
//! hybrid Ed25519 + ML-DSA-65 scheme (S-2).
//!
//! Demonstrates the intended migration path: an agent that already has a deployed
//! Ed25519 identity wraps it with [`HybridSigner::from_ed25519_secret`] instead of
//! generating a brand-new classical key, so existing peers still recognise the agent
//! by its classical public key. Also demonstrates domain-separated `sign_ctx`/
//! `verify_ctx` (S-1 parity for hybrid signers) and persisting/restoring both secret
//! key halves via `secret_key()`/`from_secret_key_bytes`.
//!
//! Requires the `hybrid` feature. Run with:
//! ```sh
//! cargo run --example hybrid_bridge --features hybrid
//! ```

use ed25519_dalek::SigningKey as Ed25519SigningKey;
use pqc_sig::hybrid::HybridSigner;
use rand::rngs::OsRng;

const AGENT_CTX: &[u8] = b"8gentz-agent-v1";
const FABRIC_CTX: &[u8] = b"8gentz-fabric-v1";

fn main() {
    // (a) Stand in for a legacy agent's already-deployed Ed25519 identity. In a real
    // migration this seed would be loaded from existing key storage, not generated.
    let legacy_key = Ed25519SigningKey::generate(&mut OsRng);
    let legacy_seed: [u8; 32] = legacy_key.to_bytes();
    let legacy_vk = legacy_key.verifying_key();
    println!("legacy Ed25519 verifying key: {} bytes", legacy_vk.to_bytes().len());

    // (b) Bridge the existing classical identity into a hybrid signer: keeps the
    // classical key as-is, generates a fresh ML-DSA-65 half.
    let signer = HybridSigner::from_ed25519_secret(&mut OsRng, &legacy_seed)
        .expect("from_ed25519_secret failed");
    let pk = signer.public_key();

    // (d) The classical half of the hybrid public key equals the legacy Ed25519
    // verifying key — existing peers can still recognise the agent by it.
    assert_eq!(
        pk.classical,
        legacy_vk.to_bytes().to_vec(),
        "hybrid classical public key must equal the legacy Ed25519 verifying key"
    );
    println!("[ok]   hybrid classical public key == legacy Ed25519 verifying key");

    // (c) Sign with a domain-separated context, verify OK under that context, and
    // confirm a different context is rejected.
    let message = b"transfer 100 credits to account #42";
    let sig = signer
        .sign_ctx(&mut OsRng, AGENT_CTX, message)
        .expect("sign_ctx failed");

    HybridSigner::verify_ctx(&pk, AGENT_CTX, message, &sig)
        .expect("signature must verify under AGENT_CTX");
    println!("[ok]   sign_ctx/verify_ctx round-trip succeeds under AGENT_CTX");

    let result = HybridSigner::verify_ctx(&pk, FABRIC_CTX, message, &sig);
    assert!(result.is_err(), "signature must NOT verify under FABRIC_CTX");
    println!(
        "[ok]   signature is REJECTED under FABRIC_CTX: {:?}",
        result.unwrap_err()
    );

    // (e) Export both secret-key halves, restore a signer from them, and confirm the
    // restored signer's public key matches the original.
    let sk = signer.secret_key();
    println!(
        "secret_key(): ed25519_seed = {} bytes, ml_dsa_65 = {} bytes",
        sk.ed25519_seed.len(),
        sk.ml_dsa_65.len()
    );

    let restored = HybridSigner::from_secret_key_bytes(&sk.ed25519_seed, &sk.ml_dsa_65)
        .expect("from_secret_key_bytes failed");
    let restored_pk = restored.public_key();
    assert_eq!(
        pk, restored_pk,
        "restored signer must have an identical public key"
    );
    println!("[ok]   secret_key() -> from_secret_key_bytes() round-trip reproduces public_key()");

    // A signature made by the restored signer must verify under the original
    // (pre-restore) public key, proving the restored secret material is identical.
    let restored_sig = restored
        .sign_ctx(&mut OsRng, AGENT_CTX, message)
        .expect("sign_ctx on restored signer failed");
    HybridSigner::verify_ctx(&pk, AGENT_CTX, message, &restored_sig)
        .expect("restored signer's signature must verify under the original public key");
    println!("[ok]   restored signer's signature verifies under the original public key");

    // (f) Sizes.
    println!("\nhybrid public key:  classical {} bytes + pqc {} bytes", pk.classical.len(), pk.pqc.len());
    println!("hybrid signature:   classical {} bytes + pqc {} bytes", sig.classical.len(), sig.pqc.len());

    println!("\nHybrid bridge demo completed successfully.");
}
