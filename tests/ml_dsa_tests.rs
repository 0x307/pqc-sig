//! Integration tests for ML-DSA (FIPS 204) — all three parameter sets.

use pqc_sig::fips204::{MlDsa44Keypair, MlDsa65Keypair, MlDsa87Keypair};
use pqc_sig::types::{SigAlgorithm, SigPublicKey, Signature, SignedMessage};
use rand::rngs::OsRng;

// ── ML-DSA-44 ─────────────────────────────────────────────────────────────────

#[test]
fn ml_dsa_44_keygen_sign_verify() {
    let keypair = MlDsa44Keypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();
    let message = b"Hello, ML-DSA-44!";
    let sig = keypair.sign(&mut OsRng, message).expect("sign failed");
    MlDsa44Keypair::verify(&pk, message, &sig).expect("verify failed");
}

#[test]
fn ml_dsa_44_wrong_message_fails() {
    let keypair = MlDsa44Keypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();
    let sig = keypair.sign(&mut OsRng, b"correct").expect("sign failed");
    assert!(MlDsa44Keypair::verify(&pk, b"wrong", &sig).is_err());
}

#[test]
fn ml_dsa_44_wrong_key_fails() {
    let kp1 = MlDsa44Keypair::generate(&mut OsRng).expect("keygen failed");
    let kp2 = MlDsa44Keypair::generate(&mut OsRng).expect("keygen failed");
    let sig = kp1.sign(&mut OsRng, b"message").expect("sign failed");
    assert!(MlDsa44Keypair::verify(&kp2.public_key(), b"message", &sig).is_err());
}

#[test]
fn ml_dsa_44_public_key_size() {
    let keypair = MlDsa44Keypair::generate(&mut OsRng).expect("keygen failed");
    assert_eq!(keypair.public_key().bytes.len(), 1312);
}

#[test]
fn ml_dsa_44_secret_key_size() {
    let keypair = MlDsa44Keypair::generate(&mut OsRng).expect("keygen failed");
    // Secret key is stored as 32-byte seed
    assert_eq!(keypair.secret_key().bytes.len(), 32);
}

#[test]
fn ml_dsa_44_signature_size() {
    let keypair = MlDsa44Keypair::generate(&mut OsRng).expect("keygen failed");
    let sig = keypair.sign(&mut OsRng, b"test").expect("sign failed");
    assert_eq!(sig.bytes.len(), 2420);
}

#[test]
fn ml_dsa_44_deterministic_sign() {
    let keypair = MlDsa44Keypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();
    let message = b"deterministic signing test";
    let sig = keypair.sign_deterministic(message).expect("sign failed");
    MlDsa44Keypair::verify(&pk, message, &sig).expect("verify failed");
}

#[test]
fn ml_dsa_44_base64url_roundtrip() {
    let keypair = MlDsa44Keypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();
    let encoded = pk.to_base64url();
    let decoded = SigPublicKey::from_base64url(SigAlgorithm::MlDsa44, &encoded)
        .expect("decode failed");
    assert_eq!(pk.bytes, decoded.bytes);
}

#[test]
fn ml_dsa_44_multibase_roundtrip() {
    let keypair = MlDsa44Keypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();
    let multibase = pk.to_multibase().expect("multibase encode failed");
    assert!(multibase.starts_with('z'));
    let decoded = SigPublicKey::from_multibase(SigAlgorithm::MlDsa44, &multibase)
        .expect("decode failed");
    assert_eq!(pk.bytes, decoded.bytes);
}

#[test]
fn ml_dsa_44_signature_json_roundtrip() {
    let keypair = MlDsa44Keypair::generate(&mut OsRng).expect("keygen failed");
    let sig = keypair.sign(&mut OsRng, b"test").expect("sign failed");
    let json = sig.to_json().expect("serialize failed");
    let decoded = Signature::from_json(&json).expect("deserialize failed");
    assert_eq!(sig.bytes, decoded.bytes);
    assert_eq!(sig.algorithm, decoded.algorithm);
}

#[test]
fn ml_dsa_44_restore_from_seed() {
    let keypair = MlDsa44Keypair::generate(&mut OsRng).expect("keygen failed");
    let sk_bytes = keypair.secret_key().bytes.clone();
    let pk_original = keypair.public_key();

    let restored = MlDsa44Keypair::from_secret_key_bytes(&sk_bytes).expect("restore failed");
    assert_eq!(pk_original.bytes, restored.public_key().bytes);
}

// ── ML-DSA-65 ─────────────────────────────────────────────────────────────────

#[test]
fn ml_dsa_65_keygen_sign_verify() {
    let keypair = MlDsa65Keypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();
    let message = b"Hello, ML-DSA-65!";
    let sig = keypair.sign(&mut OsRng, message).expect("sign failed");
    MlDsa65Keypair::verify(&pk, message, &sig).expect("verify failed");
}

#[test]
fn ml_dsa_65_wrong_message_fails() {
    let keypair = MlDsa65Keypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();
    let sig = keypair.sign(&mut OsRng, b"correct").expect("sign failed");
    assert!(MlDsa65Keypair::verify(&pk, b"wrong", &sig).is_err());
}

#[test]
fn ml_dsa_65_public_key_size() {
    let keypair = MlDsa65Keypair::generate(&mut OsRng).expect("keygen failed");
    assert_eq!(keypair.public_key().bytes.len(), 1952);
}

#[test]
fn ml_dsa_65_signature_size() {
    let keypair = MlDsa65Keypair::generate(&mut OsRng).expect("keygen failed");
    let sig = keypair.sign(&mut OsRng, b"test").expect("sign failed");
    assert_eq!(sig.bytes.len(), 3309);
}

#[test]
fn ml_dsa_65_signed_message_envelope() {
    let keypair = MlDsa65Keypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();
    let message = b"attestation payload";
    let sig = keypair.sign(&mut OsRng, message).expect("sign failed");

    let envelope = SignedMessage::new(message.to_vec(), sig.clone(), pk.clone());
    let json = envelope.to_json().expect("serialize failed");
    let decoded = SignedMessage::from_json(&json).expect("deserialize failed");

    assert_eq!(decoded.message, message);
    assert_eq!(decoded.algorithm, "ML-DSA-65");
    MlDsa65Keypair::verify(&decoded.public_key, &decoded.message, &decoded.signature)
        .expect("verify from envelope failed");
}

#[test]
fn ml_dsa_65_algorithm_mismatch_rejected() {
    let kp44 = MlDsa44Keypair::generate(&mut OsRng).expect("keygen failed");
    let kp65 = MlDsa65Keypair::generate(&mut OsRng).expect("keygen failed");
    let sig44 = kp44.sign(&mut OsRng, b"test").expect("sign failed");
    // Trying to verify a ML-DSA-44 signature with ML-DSA-65 verifier should fail
    assert!(MlDsa65Keypair::verify(&kp65.public_key(), b"test", &sig44).is_err());
}

// ── ML-DSA-87 ─────────────────────────────────────────────────────────────────

#[test]
fn ml_dsa_87_keygen_sign_verify() {
    let keypair = MlDsa87Keypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();
    let message = b"Hello, ML-DSA-87!";
    let sig = keypair.sign(&mut OsRng, message).expect("sign failed");
    MlDsa87Keypair::verify(&pk, message, &sig).expect("verify failed");
}

#[test]
fn ml_dsa_87_wrong_message_fails() {
    let keypair = MlDsa87Keypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();
    let sig = keypair.sign(&mut OsRng, b"correct").expect("sign failed");
    assert!(MlDsa87Keypair::verify(&pk, b"wrong", &sig).is_err());
}

#[test]
fn ml_dsa_87_public_key_size() {
    let keypair = MlDsa87Keypair::generate(&mut OsRng).expect("keygen failed");
    assert_eq!(keypair.public_key().bytes.len(), 2592);
}

#[test]
fn ml_dsa_87_signature_size() {
    let keypair = MlDsa87Keypair::generate(&mut OsRng).expect("keygen failed");
    let sig = keypair.sign(&mut OsRng, b"test").expect("sign failed");
    assert_eq!(sig.bytes.len(), 4627);
}

#[test]
fn ml_dsa_87_large_message() {
    let keypair = MlDsa87Keypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();
    let message = vec![0xABu8; 65536]; // 64 KB message
    let sig = keypair.sign(&mut OsRng, &message).expect("sign failed");
    MlDsa87Keypair::verify(&pk, &message, &sig).expect("verify failed");
}

#[test]
fn ml_dsa_87_empty_message() {
    let keypair = MlDsa87Keypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();
    let sig = keypair.sign(&mut OsRng, b"").expect("sign empty message failed");
    MlDsa87Keypair::verify(&pk, b"", &sig).expect("verify empty message failed");
}
