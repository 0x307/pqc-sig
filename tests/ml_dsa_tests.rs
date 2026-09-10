//! Integration tests for ML-DSA (FIPS 204) — all three parameter sets.

use pqc_sig::fips204::{MlDsa44Keypair, MlDsa65Keypair, MlDsa87Keypair};
use pqc_sig::prehash::PreHash;
use pqc_sig::types::{SigAlgorithm, SigPublicKey, Signature, SignedMessage};
use pqc_sig::SigError;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256, Sha384, Sha512};

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

// ── Domain separation: sign_ctx / sign_ctx_deterministic / verify_ctx (S-1) ───

#[test]
fn ml_dsa_44_sign_ctx_roundtrip_and_wrong_ctx_rejected() {
    let keypair = MlDsa44Keypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();
    let message = b"ml-dsa-44 ctx roundtrip";
    let sig = keypair
        .sign_ctx(&mut OsRng, b"8gentz-agent-v1", message)
        .expect("sign_ctx failed");
    MlDsa44Keypair::verify_ctx(&pk, b"8gentz-agent-v1", message, &sig)
        .expect("verify_ctx with matching ctx must succeed");

    let err = MlDsa44Keypair::verify_ctx(&pk, b"8gentz-fabric-v1", message, &sig)
        .expect_err("verify_ctx with wrong ctx must fail");
    assert_eq!(err, SigError::VerificationFailed);
}

#[test]
fn ml_dsa_65_sign_ctx_roundtrip_and_wrong_ctx_rejected() {
    let keypair = MlDsa65Keypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();
    let message = b"ml-dsa-65 ctx roundtrip";
    let sig = keypair
        .sign_ctx(&mut OsRng, b"8gentz-agent-v1", message)
        .expect("sign_ctx failed");
    MlDsa65Keypair::verify_ctx(&pk, b"8gentz-agent-v1", message, &sig)
        .expect("verify_ctx with matching ctx must succeed");

    let err = MlDsa65Keypair::verify_ctx(&pk, b"8gentz-fabric-v1", message, &sig)
        .expect_err("verify_ctx with wrong ctx must fail");
    assert_eq!(err, SigError::VerificationFailed);
}

#[test]
fn ml_dsa_87_sign_ctx_roundtrip_and_wrong_ctx_rejected() {
    let keypair = MlDsa87Keypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();
    let message = b"ml-dsa-87 ctx roundtrip";
    let sig = keypair
        .sign_ctx(&mut OsRng, b"8gentz-agent-v1", message)
        .expect("sign_ctx failed");
    MlDsa87Keypair::verify_ctx(&pk, b"8gentz-agent-v1", message, &sig)
        .expect("verify_ctx with matching ctx must succeed");

    let err = MlDsa87Keypair::verify_ctx(&pk, b"8gentz-fabric-v1", message, &sig)
        .expect_err("verify_ctx with wrong ctx must fail");
    assert_eq!(err, SigError::VerificationFailed);
}

#[test]
fn ml_dsa_65_empty_ctx_interoperates_with_legacy_api() {
    let keypair = MlDsa65Keypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();
    let message = b"empty ctx interop";

    // sign_ctx_deterministic(&[], m) must be byte-identical to sign_deterministic(m),
    // and verifiable via the legacy verify().
    let ctx_sig = keypair
        .sign_ctx_deterministic(&[], message)
        .expect("sign_ctx_deterministic failed");
    let legacy_sig = keypair.sign_deterministic(message).expect("sign_deterministic failed");
    assert_eq!(ctx_sig.bytes, legacy_sig.bytes);
    MlDsa65Keypair::verify(&pk, message, &ctx_sig).expect("legacy verify() must accept empty-ctx signature");

    // sign (legacy) must be verifiable via verify_ctx(pk, &[], ..).
    let legacy_sig2 = keypair.sign(&mut OsRng, message).expect("sign failed");
    MlDsa65Keypair::verify_ctx(&pk, &[], message, &legacy_sig2)
        .expect("verify_ctx with empty ctx must accept legacy sign() signature");
}

#[test]
fn ml_dsa_65_ctx_length_boundary() {
    let keypair = MlDsa65Keypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();
    let message = b"ctx length boundary";

    // Exactly 255 bytes must succeed.
    let ctx_255 = vec![0x42u8; 255];
    let sig = keypair
        .sign_ctx(&mut OsRng, &ctx_255, message)
        .expect("sign_ctx with 255-byte ctx must succeed");
    MlDsa65Keypair::verify_ctx(&pk, &ctx_255, message, &sig)
        .expect("verify_ctx with 255-byte ctx must succeed");

    // 256 bytes must fail with ContextTooLong on both sign and verify.
    let ctx_256 = vec![0x42u8; 256];
    let err = keypair
        .sign_ctx(&mut OsRng, &ctx_256, message)
        .expect_err("sign_ctx with 256-byte ctx must fail");
    assert_eq!(err, SigError::ContextTooLong { len: 256 });

    let err = MlDsa65Keypair::verify_ctx(&pk, &ctx_256, message, &sig)
        .expect_err("verify_ctx with 256-byte ctx must fail");
    assert_eq!(err, SigError::ContextTooLong { len: 256 });
}

#[test]
fn ml_dsa_65_sign_ctx_deterministic_is_deterministic() {
    let keypair = MlDsa65Keypair::generate(&mut OsRng).expect("keygen failed");
    let message = b"deterministic ctx signing";
    let ctx = b"8gentz-agent-v1";

    let sig1 = keypair.sign_ctx_deterministic(ctx, message).expect("sign 1 failed");
    let sig2 = keypair.sign_ctx_deterministic(ctx, message).expect("sign 2 failed");
    assert_eq!(sig1.bytes, sig2.bytes, "sign_ctx_deterministic must be deterministic");
}

// ── Pre-hash signing: sign_prehash / sign_prehash_deterministic / verify_prehash (S-4) ─

#[test]
fn ml_dsa_44_prehash_roundtrip_sha256() {
    let keypair = MlDsa44Keypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();
    let digest = Sha256::digest(b"a large module's worth of bytes, hashed once");
    let sig = keypair
        .sign_prehash(&mut OsRng, b"8gentz-module-v1", PreHash::Sha256, &digest)
        .expect("sign_prehash failed");
    MlDsa44Keypair::verify_prehash(&pk, b"8gentz-module-v1", PreHash::Sha256, &digest, &sig)
        .expect("verify_prehash failed");
}

#[test]
fn ml_dsa_65_prehash_roundtrip_sha384_and_sha512_and_shake256() {
    let keypair = MlDsa65Keypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();
    let message = b"a large module's worth of bytes, hashed once";

    let digest384 = Sha384::digest(message);
    let sig384 = keypair
        .sign_prehash(&mut OsRng, b"8gentz-module-v1", PreHash::Sha384, &digest384)
        .expect("sign_prehash (SHA-384) failed");
    MlDsa65Keypair::verify_prehash(&pk, b"8gentz-module-v1", PreHash::Sha384, &digest384, &sig384)
        .expect("verify_prehash (SHA-384) failed");

    let digest512 = Sha512::digest(message);
    let sig512 = keypair
        .sign_prehash(&mut OsRng, b"8gentz-module-v1", PreHash::Sha512, &digest512)
        .expect("sign_prehash (SHA-512) failed");
    MlDsa65Keypair::verify_prehash(&pk, b"8gentz-module-v1", PreHash::Sha512, &digest512, &sig512)
        .expect("verify_prehash (SHA-512) failed");

    // SHAKE256 (64-byte output, 256-bit collision strength) — use SHA-512 bytes as a
    // stand-in digest of the correct length; only the framing/strength are tested here.
    let shake_digest = digest512; // 64 bytes, matches PreHash::Shake256::digest_len()
    let sig_shake = keypair
        .sign_prehash(&mut OsRng, b"8gentz-module-v1", PreHash::Shake256, &shake_digest)
        .expect("sign_prehash (SHAKE256) failed");
    MlDsa65Keypair::verify_prehash(&pk, b"8gentz-module-v1", PreHash::Shake256, &shake_digest, &sig_shake)
        .expect("verify_prehash (SHAKE256) failed");
}

#[test]
fn ml_dsa_87_prehash_roundtrip_sha512() {
    let keypair = MlDsa87Keypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();
    let digest = Sha512::digest(b"a large module's worth of bytes, hashed once");
    let sig = keypair
        .sign_prehash(&mut OsRng, b"8gentz-module-v1", PreHash::Sha512, &digest)
        .expect("sign_prehash failed");
    MlDsa87Keypair::verify_prehash(&pk, b"8gentz-module-v1", PreHash::Sha512, &digest, &sig)
        .expect("verify_prehash failed");
}

#[test]
fn ml_dsa_65_sign_prehash_deterministic_is_deterministic() {
    let keypair = MlDsa65Keypair::generate(&mut OsRng).expect("keygen failed");
    let digest = Sha512::digest(b"deterministic prehash test");
    let ctx = b"8gentz-module-v1";

    let sig1 = keypair
        .sign_prehash_deterministic(ctx, PreHash::Sha512, &digest)
        .expect("sign 1 failed");
    let sig2 = keypair
        .sign_prehash_deterministic(ctx, PreHash::Sha512, &digest)
        .expect("sign 2 failed");
    assert_eq!(sig1.bytes, sig2.bytes, "sign_prehash_deterministic must be deterministic");
}

#[test]
fn ml_dsa_65_prehash_wrong_ctx_fails() {
    let keypair = MlDsa65Keypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();
    let digest = Sha512::digest(b"module bytes");
    let sig = keypair
        .sign_prehash_deterministic(b"8gentz-agent-v1", PreHash::Sha512, &digest)
        .expect("sign_prehash_deterministic failed");

    let err = MlDsa65Keypair::verify_prehash(&pk, b"8gentz-fabric-v1", PreHash::Sha512, &digest, &sig)
        .expect_err("verify_prehash with wrong ctx must fail");
    assert_eq!(err, SigError::VerificationFailed);
}

#[test]
fn ml_dsa_65_prehash_tampered_digest_fails() {
    let keypair = MlDsa65Keypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();
    let digest = Sha512::digest(b"module bytes");
    let sig = keypair
        .sign_prehash_deterministic(b"8gentz-module-v1", PreHash::Sha512, &digest)
        .expect("sign_prehash_deterministic failed");

    let mut tampered = digest.to_vec();
    tampered[0] ^= 0xFF;
    let err = MlDsa65Keypair::verify_prehash(&pk, b"8gentz-module-v1", PreHash::Sha512, &tampered, &sig)
        .expect_err("verify_prehash with tampered digest must fail");
    assert_eq!(err, SigError::VerificationFailed);
}

#[test]
fn ml_dsa_65_prehash_strength_enforcement() {
    let keypair65 = MlDsa65Keypair::generate(&mut OsRng).expect("keygen failed");
    let keypair87 = MlDsa87Keypair::generate(&mut OsRng).expect("keygen failed");
    let keypair44 = MlDsa44Keypair::generate(&mut OsRng).expect("keygen failed");
    let digest256 = Sha256::digest(b"module bytes");
    let digest384 = Sha384::digest(b"module bytes");

    // SHA-256 (128 bits) is too weak for ML-DSA-65 (192 bits) and ML-DSA-87 (256 bits).
    let err = keypair65
        .sign_prehash_deterministic(b"8gentz-module-v1", PreHash::Sha256, &digest256)
        .expect_err("ML-DSA-65 must reject SHA-256 prehash");
    assert_eq!(
        err,
        SigError::PreHashTooWeak { hash: "SHA-256", strength: 128, algorithm: "ML-DSA-65", required: 192 }
    );
    let err = keypair87
        .sign_prehash_deterministic(b"8gentz-module-v1", PreHash::Sha256, &digest256)
        .expect_err("ML-DSA-87 must reject SHA-256 prehash");
    assert_eq!(
        err,
        SigError::PreHashTooWeak { hash: "SHA-256", strength: 128, algorithm: "ML-DSA-87", required: 256 }
    );

    // SHA-256 (128 bits) is sufficient for ML-DSA-44 (128 bits).
    keypair44
        .sign_prehash_deterministic(b"8gentz-module-v1", PreHash::Sha256, &digest256)
        .expect("ML-DSA-44 must accept SHA-256 prehash");

    // SHA-384 (192 bits) is too weak for ML-DSA-87 (256 bits).
    let err = keypair87
        .sign_prehash_deterministic(b"8gentz-module-v1", PreHash::Sha384, &digest384)
        .expect_err("ML-DSA-87 must reject SHA-384 prehash");
    assert_eq!(
        err,
        SigError::PreHashTooWeak { hash: "SHA-384", strength: 192, algorithm: "ML-DSA-87", required: 256 }
    );

    // The same enforcement applies on verify_prehash.
    let pk87 = keypair87.public_key();
    let sig = keypair87
        .sign_prehash_deterministic(b"8gentz-module-v1", PreHash::Sha512, &Sha512::digest(b"module bytes"))
        .expect("sign with sufficient strength failed");
    let err = MlDsa87Keypair::verify_prehash(&pk87, b"8gentz-module-v1", PreHash::Sha256, &digest256, &sig)
        .expect_err("verify_prehash must also reject SHA-256 for ML-DSA-87");
    assert_eq!(
        err,
        SigError::PreHashTooWeak { hash: "SHA-256", strength: 128, algorithm: "ML-DSA-87", required: 256 }
    );
}

#[test]
fn ml_dsa_65_prehash_invalid_digest_length() {
    let keypair = MlDsa65Keypair::generate(&mut OsRng).expect("keygen failed");
    let short_digest = [0u8; 31]; // SHA-256 wants 32 bytes
    let err = keypair
        .sign_prehash_deterministic(b"8gentz-module-v1", PreHash::Sha256, &short_digest)
        .expect_err("31-byte digest must be rejected for SHA-256");
    assert_eq!(
        err,
        SigError::InvalidDigestLength { hash: "SHA-256", expected: 32, got: 31 }
    );
}

#[test]
fn ml_dsa_65_prehash_ctx_length_boundary() {
    let keypair = MlDsa65Keypair::generate(&mut OsRng).expect("keygen failed");
    let digest = Sha512::digest(b"module bytes");

    let ctx_256 = vec![0x42u8; 256];
    let err = keypair
        .sign_prehash_deterministic(&ctx_256, PreHash::Sha512, &digest)
        .expect_err("sign_prehash_deterministic with 256-byte ctx must fail");
    assert_eq!(err, SigError::ContextTooLong { len: 256 });
}

#[test]
fn ml_dsa_65_prehash_signature_does_not_verify_via_plain_verify_or_verify_ctx() {
    let keypair = MlDsa65Keypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();
    let ctx = b"8gentz-module-v1";
    let digest = Sha512::digest(b"module bytes");

    let prehash_sig = keypair
        .sign_prehash_deterministic(ctx, PreHash::Sha512, &digest)
        .expect("sign_prehash_deterministic failed");

    // Neither plain verify() nor verify_ctx() over the digest (or the framed M') bytes
    // accept a HashML-DSA signature — the 0x01 domain byte separates the two modes.
    assert!(MlDsa65Keypair::verify(&pk, &digest, &prehash_sig).is_err());
    assert!(MlDsa65Keypair::verify_ctx(&pk, ctx, &digest, &prehash_sig).is_err());
    assert!(MlDsa65Keypair::verify_ctx(&pk, &[], &digest, &prehash_sig).is_err());
}

#[test]
fn ml_dsa_65_prehash_domain_byte_differs_from_pure_ctx_signing() {
    // Structural proof that the 0x01 domain byte is actually in effect: a signature
    // produced by sign_ctx_deterministic(ctx, OID || digest) — i.e. pure mode (domain
    // byte 0x00) over the same OID+digest bytes HashML-DSA would frame — must NOT
    // verify via verify_prehash.
    let keypair = MlDsa65Keypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();
    let ctx = b"8gentz-module-v1";
    let digest = Sha512::digest(b"module bytes");

    let oid = PreHash::Sha512.oid_der();
    let mut oid_and_digest = oid.to_vec();
    oid_and_digest.extend_from_slice(&digest);

    let pure_sig = keypair
        .sign_ctx_deterministic(ctx, &oid_and_digest)
        .expect("sign_ctx_deterministic failed");

    let err = MlDsa65Keypair::verify_prehash(&pk, ctx, PreHash::Sha512, &digest, &pure_sig)
        .expect_err("a pure-mode (0x00) signature must not verify as HashML-DSA (0x01)");
    assert_eq!(err, SigError::VerificationFailed);
}
