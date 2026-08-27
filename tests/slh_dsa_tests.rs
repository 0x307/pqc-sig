//! Integration tests for SLH-DSA (FIPS 205) — selected parameter sets.
//!
//! Note: Full tests for all 12 parameter sets would be very slow due to large
//! signature sizes. We test representative sets from each family.

use pqc_sig::fips205::{
    SlhDsaSha2_128sKeypair, SlhDsaSha2_128fKeypair,
    SlhDsaSha2_192sKeypair, SlhDsaSha2_256sKeypair,
    SlhDsaShake128sKeypair, SlhDsaShake128fKeypair,
    SlhDsaShake256sKeypair,
};
use pqc_sig::types::SigAlgorithm;
use rand::rngs::OsRng;

// ── SHA2 variants ─────────────────────────────────────────────────────────────

#[test]
fn slh_dsa_sha2_128s_keygen_sign_verify() {
    let keypair = SlhDsaSha2_128sKeypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();
    let message = b"Hello, SLH-DSA-SHA2-128s!";
    let sig = keypair.sign(&mut OsRng, message).expect("sign failed");
    SlhDsaSha2_128sKeypair::verify(&pk, message, &sig).expect("verify failed");
}

#[test]
fn slh_dsa_sha2_128s_wrong_message_fails() {
    let keypair = SlhDsaSha2_128sKeypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();
    let sig = keypair.sign(&mut OsRng, b"correct").expect("sign failed");
    assert!(SlhDsaSha2_128sKeypair::verify(&pk, b"wrong", &sig).is_err());
}

#[test]
fn slh_dsa_sha2_128s_public_key_size() {
    let keypair = SlhDsaSha2_128sKeypair::generate(&mut OsRng).expect("keygen failed");
    assert_eq!(keypair.public_key().bytes.len(), 32);
    assert_eq!(keypair.public_key().algorithm, SigAlgorithm::SlhDsaSha2_128s);
}

#[test]
fn slh_dsa_sha2_128s_signature_size() {
    let keypair = SlhDsaSha2_128sKeypair::generate(&mut OsRng).expect("keygen failed");
    let sig = keypair.sign(&mut OsRng, b"test").expect("sign failed");
    assert_eq!(sig.bytes.len(), 7856);
}

#[test]
fn slh_dsa_sha2_128s_deterministic_sign() {
    let keypair = SlhDsaSha2_128sKeypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();
    let message = b"deterministic test";
    let sig = keypair.sign_deterministic(message).expect("sign failed");
    SlhDsaSha2_128sKeypair::verify(&pk, message, &sig).expect("verify failed");
}

#[test]
fn slh_dsa_sha2_128s_randomized_signs_differ() {
    let keypair = SlhDsaSha2_128sKeypair::generate(&mut OsRng).expect("keygen failed");
    let message = b"same message";
    let sig1 = keypair.sign(&mut OsRng, message).expect("sign 1 failed");
    let sig2 = keypair.sign(&mut OsRng, message).expect("sign 2 failed");
    // Randomized signatures over the same message should differ
    assert_ne!(sig1.bytes, sig2.bytes, "randomized signatures should differ");
}

#[test]
fn slh_dsa_sha2_128f_keygen_sign_verify() {
    let keypair = SlhDsaSha2_128fKeypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();
    let message = b"Hello, SLH-DSA-SHA2-128f!";
    let sig = keypair.sign(&mut OsRng, message).expect("sign failed");
    SlhDsaSha2_128fKeypair::verify(&pk, message, &sig).expect("verify failed");
}

#[test]
fn slh_dsa_sha2_128f_signature_size() {
    let keypair = SlhDsaSha2_128fKeypair::generate(&mut OsRng).expect("keygen failed");
    let sig = keypair.sign(&mut OsRng, b"test").expect("sign failed");
    assert_eq!(sig.bytes.len(), 17088);
}

#[test]
fn slh_dsa_sha2_192s_keygen_sign_verify() {
    let keypair = SlhDsaSha2_192sKeypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();
    let message = b"Hello, SLH-DSA-SHA2-192s!";
    let sig = keypair.sign(&mut OsRng, message).expect("sign failed");
    SlhDsaSha2_192sKeypair::verify(&pk, message, &sig).expect("verify failed");
}

#[test]
fn slh_dsa_sha2_192s_public_key_size() {
    let keypair = SlhDsaSha2_192sKeypair::generate(&mut OsRng).expect("keygen failed");
    assert_eq!(keypair.public_key().bytes.len(), 48);
}

#[test]
fn slh_dsa_sha2_256s_keygen_sign_verify() {
    let keypair = SlhDsaSha2_256sKeypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();
    let message = b"Hello, SLH-DSA-SHA2-256s!";
    let sig = keypair.sign(&mut OsRng, message).expect("sign failed");
    SlhDsaSha2_256sKeypair::verify(&pk, message, &sig).expect("verify failed");
}

#[test]
fn slh_dsa_sha2_256s_public_key_size() {
    let keypair = SlhDsaSha2_256sKeypair::generate(&mut OsRng).expect("keygen failed");
    assert_eq!(keypair.public_key().bytes.len(), 64);
}

// ── SHAKE variants ────────────────────────────────────────────────────────────

#[test]
fn slh_dsa_shake_128s_keygen_sign_verify() {
    let keypair = SlhDsaShake128sKeypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();
    let message = b"Hello, SLH-DSA-SHAKE-128s!";
    let sig = keypair.sign(&mut OsRng, message).expect("sign failed");
    SlhDsaShake128sKeypair::verify(&pk, message, &sig).expect("verify failed");
}

#[test]
fn slh_dsa_shake_128s_wrong_message_fails() {
    let keypair = SlhDsaShake128sKeypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();
    let sig = keypair.sign(&mut OsRng, b"correct").expect("sign failed");
    assert!(SlhDsaShake128sKeypair::verify(&pk, b"wrong", &sig).is_err());
}

#[test]
fn slh_dsa_shake_128s_public_key_size() {
    let keypair = SlhDsaShake128sKeypair::generate(&mut OsRng).expect("keygen failed");
    assert_eq!(keypair.public_key().bytes.len(), 32);
    assert_eq!(keypair.public_key().algorithm, SigAlgorithm::SlhDsaShake128s);
}

#[test]
fn slh_dsa_shake_128f_keygen_sign_verify() {
    let keypair = SlhDsaShake128fKeypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();
    let message = b"Hello, SLH-DSA-SHAKE-128f!";
    let sig = keypair.sign(&mut OsRng, message).expect("sign failed");
    SlhDsaShake128fKeypair::verify(&pk, message, &sig).expect("verify failed");
}

#[test]
fn slh_dsa_shake_256s_keygen_sign_verify() {
    let keypair = SlhDsaShake256sKeypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();
    let message = b"Hello, SLH-DSA-SHAKE-256s!";
    let sig = keypair.sign(&mut OsRng, message).expect("sign failed");
    SlhDsaShake256sKeypair::verify(&pk, message, &sig).expect("verify failed");
}

#[test]
fn slh_dsa_shake_256s_public_key_size() {
    let keypair = SlhDsaShake256sKeypair::generate(&mut OsRng).expect("keygen failed");
    assert_eq!(keypair.public_key().bytes.len(), 64);
}

// ── Cross-algorithm rejection ─────────────────────────────────────────────────

#[test]
fn slh_dsa_cross_algorithm_rejected() {
    let kp_sha2 = SlhDsaSha2_128sKeypair::generate(&mut OsRng).expect("keygen failed");
    let kp_shake = SlhDsaShake128sKeypair::generate(&mut OsRng).expect("keygen failed");
    let sig = kp_sha2.sign(&mut OsRng, b"test").expect("sign failed");
    // SHA2 signature should be rejected by SHAKE verifier
    assert!(SlhDsaShake128sKeypair::verify(&kp_shake.public_key(), b"test", &sig).is_err());
}

// ── Restore from bytes ────────────────────────────────────────────────────────

#[test]
fn slh_dsa_sha2_128s_restore_from_bytes() {
    let keypair = SlhDsaSha2_128sKeypair::generate(&mut OsRng).expect("keygen failed");
    let sk_bytes = keypair.secret_key().bytes.clone();
    let pk_original = keypair.public_key();

    let restored = SlhDsaSha2_128sKeypair::from_secret_key_bytes(&sk_bytes)
        .expect("restore failed");
    assert_eq!(pk_original.bytes, restored.public_key().bytes);
}
