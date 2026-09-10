//! Integration tests for SLH-DSA (FIPS 205) — selected parameter sets.
//!
//! Note: Full tests for all 12 parameter sets would be very slow due to large
//! signature sizes. We test representative sets from each family.

use pqc_sig::fips205::{
    SlhDsaSha2_128sKeypair, SlhDsaSha2_128fKeypair,
    SlhDsaSha2_192sKeypair, SlhDsaSha2_192fKeypair,
    SlhDsaSha2_256sKeypair, SlhDsaSha2_256fKeypair,
    SlhDsaShake128sKeypair, SlhDsaShake128fKeypair,
    SlhDsaShake256sKeypair,
};
use pqc_sig::prehash::PreHash;
use pqc_sig::types::SigAlgorithm;
use pqc_sig::SigError;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256, Sha384, Sha512};

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

// ── Domain separation: sign_ctx / sign_ctx_deterministic / verify_ctx (S-1) ───
//
// Covers all six SHA2 parameter sets plus two SHAKE parameter sets, per the S-1 test
// plan. SHAKE coverage is intentionally limited (slow signatures).

macro_rules! slh_dsa_ctx_roundtrip_test {
    ($name:ident, $keypair:ty, $alg_name:literal) => {
        #[test]
        fn $name() {
            let keypair = <$keypair>::generate(&mut OsRng).expect("keygen failed");
            let pk = keypair.public_key();
            let message = concat!("ctx roundtrip for ", $alg_name).as_bytes();
            let sig = keypair
                .sign_ctx(&mut OsRng, b"8gentz-agent-v1", message)
                .expect("sign_ctx failed");
            <$keypair>::verify_ctx(&pk, b"8gentz-agent-v1", message, &sig)
                .expect("verify_ctx with matching ctx must succeed");

            let err = <$keypair>::verify_ctx(&pk, b"8gentz-fabric-v1", message, &sig)
                .expect_err("verify_ctx with wrong ctx must fail");
            assert_eq!(err, SigError::VerificationFailed);
        }
    };
}

slh_dsa_ctx_roundtrip_test!(slh_dsa_sha2_128s_sign_ctx_roundtrip, SlhDsaSha2_128sKeypair, "SLH-DSA-SHA2-128s");
slh_dsa_ctx_roundtrip_test!(slh_dsa_sha2_128f_sign_ctx_roundtrip, SlhDsaSha2_128fKeypair, "SLH-DSA-SHA2-128f");
slh_dsa_ctx_roundtrip_test!(slh_dsa_sha2_192s_sign_ctx_roundtrip, SlhDsaSha2_192sKeypair, "SLH-DSA-SHA2-192s");
slh_dsa_ctx_roundtrip_test!(slh_dsa_sha2_192f_sign_ctx_roundtrip, SlhDsaSha2_192fKeypair, "SLH-DSA-SHA2-192f");
slh_dsa_ctx_roundtrip_test!(slh_dsa_sha2_256s_sign_ctx_roundtrip, SlhDsaSha2_256sKeypair, "SLH-DSA-SHA2-256s");
slh_dsa_ctx_roundtrip_test!(slh_dsa_sha2_256f_sign_ctx_roundtrip, SlhDsaSha2_256fKeypair, "SLH-DSA-SHA2-256f");
slh_dsa_ctx_roundtrip_test!(slh_dsa_shake_128s_sign_ctx_roundtrip, SlhDsaShake128sKeypair, "SLH-DSA-SHAKE-128s");
slh_dsa_ctx_roundtrip_test!(slh_dsa_shake_256s_sign_ctx_roundtrip, SlhDsaShake256sKeypair, "SLH-DSA-SHAKE-256s");

#[test]
fn slh_dsa_sha2_128s_empty_ctx_interoperates_with_legacy_api() {
    let keypair = SlhDsaSha2_128sKeypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();
    let message = b"empty ctx interop";

    // sign_ctx_deterministic(&[], m) must be byte-identical to sign_deterministic(m),
    // and verifiable via the legacy verify().
    let ctx_sig = keypair
        .sign_ctx_deterministic(&[], message)
        .expect("sign_ctx_deterministic failed");
    let legacy_sig = keypair.sign_deterministic(message).expect("sign_deterministic failed");
    assert_eq!(ctx_sig.bytes, legacy_sig.bytes);
    SlhDsaSha2_128sKeypair::verify(&pk, message, &ctx_sig)
        .expect("legacy verify() must accept empty-ctx signature");

    // Legacy sign() must be verifiable via verify_ctx(pk, &[], ..).
    let legacy_sig2 = keypair.sign(&mut OsRng, message).expect("sign failed");
    SlhDsaSha2_128sKeypair::verify_ctx(&pk, &[], message, &legacy_sig2)
        .expect("verify_ctx with empty ctx must accept legacy sign() signature");
}

#[test]
fn slh_dsa_sha2_128s_ctx_length_boundary() {
    let keypair = SlhDsaSha2_128sKeypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();
    let message = b"ctx length boundary";

    // Exactly 255 bytes must succeed.
    let ctx_255 = vec![0x42u8; 255];
    let sig = keypair
        .sign_ctx(&mut OsRng, &ctx_255, message)
        .expect("sign_ctx with 255-byte ctx must succeed");
    SlhDsaSha2_128sKeypair::verify_ctx(&pk, &ctx_255, message, &sig)
        .expect("verify_ctx with 255-byte ctx must succeed");

    // 256 bytes must fail with ContextTooLong on both sign and verify.
    let ctx_256 = vec![0x42u8; 256];
    let err = keypair
        .sign_ctx(&mut OsRng, &ctx_256, message)
        .expect_err("sign_ctx with 256-byte ctx must fail");
    assert_eq!(err, SigError::ContextTooLong { len: 256 });

    let err = SlhDsaSha2_128sKeypair::verify_ctx(&pk, &ctx_256, message, &sig)
        .expect_err("verify_ctx with 256-byte ctx must fail");
    assert_eq!(err, SigError::ContextTooLong { len: 256 });
}

#[test]
fn slh_dsa_sha2_128s_sign_ctx_deterministic_is_deterministic() {
    let keypair = SlhDsaSha2_128sKeypair::generate(&mut OsRng).expect("keygen failed");
    let message = b"deterministic ctx signing";
    let ctx = b"8gentz-agent-v1";

    let sig1 = keypair.sign_ctx_deterministic(ctx, message).expect("sign 1 failed");
    let sig2 = keypair.sign_ctx_deterministic(ctx, message).expect("sign 2 failed");
    assert_eq!(sig1.bytes, sig2.bytes, "sign_ctx_deterministic must be deterministic");
}

// ── Pre-hash signing: sign_prehash / sign_prehash_deterministic / verify_prehash (S-4) ─
//
// Covers all six SHA2 parameter sets plus one SHAKE parameter set, per the S-4 test
// plan. SHAKE coverage is intentionally limited (slow signatures).

macro_rules! slh_dsa_prehash_roundtrip_test {
    ($name:ident, $keypair:ty, $hash:expr, $digest:expr) => {
        #[test]
        fn $name() {
            let keypair = <$keypair>::generate(&mut OsRng).expect("keygen failed");
            let pk = keypair.public_key();
            let digest = $digest;
            let sig = keypair
                .sign_prehash(&mut OsRng, b"8gentz-module-v1", $hash, &digest)
                .expect("sign_prehash failed");
            <$keypair>::verify_prehash(&pk, b"8gentz-module-v1", $hash, &digest, &sig)
                .expect("verify_prehash failed");
        }
    };
}

slh_dsa_prehash_roundtrip_test!(
    slh_dsa_sha2_128s_prehash_roundtrip, SlhDsaSha2_128sKeypair,
    PreHash::Sha256, Sha256::digest(b"module bytes for SLH-DSA-SHA2-128s").to_vec()
);
slh_dsa_prehash_roundtrip_test!(
    slh_dsa_sha2_128f_prehash_roundtrip, SlhDsaSha2_128fKeypair,
    PreHash::Sha256, Sha256::digest(b"module bytes for SLH-DSA-SHA2-128f").to_vec()
);
slh_dsa_prehash_roundtrip_test!(
    slh_dsa_sha2_192s_prehash_roundtrip, SlhDsaSha2_192sKeypair,
    PreHash::Sha384, Sha384::digest(b"module bytes for SLH-DSA-SHA2-192s").to_vec()
);
slh_dsa_prehash_roundtrip_test!(
    slh_dsa_sha2_192f_prehash_roundtrip, SlhDsaSha2_192fKeypair,
    PreHash::Sha384, Sha384::digest(b"module bytes for SLH-DSA-SHA2-192f").to_vec()
);
slh_dsa_prehash_roundtrip_test!(
    slh_dsa_sha2_256s_prehash_roundtrip, SlhDsaSha2_256sKeypair,
    PreHash::Sha512, Sha512::digest(b"module bytes for SLH-DSA-SHA2-256s").to_vec()
);
slh_dsa_prehash_roundtrip_test!(
    slh_dsa_sha2_256f_prehash_roundtrip, SlhDsaSha2_256fKeypair,
    PreHash::Sha512, Sha512::digest(b"module bytes for SLH-DSA-SHA2-256f").to_vec()
);
slh_dsa_prehash_roundtrip_test!(
    slh_dsa_shake_256s_prehash_roundtrip, SlhDsaShake256sKeypair,
    PreHash::Shake256, Sha512::digest(b"module bytes for SLH-DSA-SHAKE-256s").to_vec()
);

#[test]
fn slh_dsa_sha2_128s_sign_prehash_deterministic_is_deterministic() {
    let keypair = SlhDsaSha2_128sKeypair::generate(&mut OsRng).expect("keygen failed");
    let digest = Sha256::digest(b"deterministic prehash test");
    let ctx = b"8gentz-module-v1";

    let sig1 = keypair
        .sign_prehash_deterministic(ctx, PreHash::Sha256, &digest)
        .expect("sign 1 failed");
    let sig2 = keypair
        .sign_prehash_deterministic(ctx, PreHash::Sha256, &digest)
        .expect("sign 2 failed");
    assert_eq!(sig1.bytes, sig2.bytes, "sign_prehash_deterministic must be deterministic");
}

#[test]
fn slh_dsa_sha2_128s_prehash_wrong_ctx_fails() {
    let keypair = SlhDsaSha2_128sKeypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();
    let digest = Sha256::digest(b"module bytes");
    let sig = keypair
        .sign_prehash_deterministic(b"8gentz-agent-v1", PreHash::Sha256, &digest)
        .expect("sign_prehash_deterministic failed");

    let err = SlhDsaSha2_128sKeypair::verify_prehash(&pk, b"8gentz-fabric-v1", PreHash::Sha256, &digest, &sig)
        .expect_err("verify_prehash with wrong ctx must fail");
    assert_eq!(err, SigError::VerificationFailed);
}

#[test]
fn slh_dsa_sha2_128s_prehash_tampered_digest_fails() {
    let keypair = SlhDsaSha2_128sKeypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();
    let digest = Sha256::digest(b"module bytes");
    let sig = keypair
        .sign_prehash_deterministic(b"8gentz-module-v1", PreHash::Sha256, &digest)
        .expect("sign_prehash_deterministic failed");

    let mut tampered = digest.to_vec();
    tampered[0] ^= 0xFF;
    let err = SlhDsaSha2_128sKeypair::verify_prehash(&pk, b"8gentz-module-v1", PreHash::Sha256, &tampered, &sig)
        .expect_err("verify_prehash with tampered digest must fail");
    assert_eq!(err, SigError::VerificationFailed);
}

#[test]
fn slh_dsa_sha2_192s_prehash_strength_enforcement() {
    // SHA-256 (128 bits) is too weak for SLH-DSA-SHA2-192s (192 bits).
    let keypair = SlhDsaSha2_192sKeypair::generate(&mut OsRng).expect("keygen failed");
    let digest = Sha256::digest(b"module bytes");
    let err = keypair
        .sign_prehash_deterministic(b"8gentz-module-v1", PreHash::Sha256, &digest)
        .expect_err("SLH-DSA-SHA2-192s must reject SHA-256 prehash");
    assert_eq!(
        err,
        SigError::PreHashTooWeak { hash: "SHA-256", strength: 128, algorithm: "SLH-DSA-SHA2-192s", required: 192 }
    );
}

#[test]
fn slh_dsa_sha2_128s_prehash_invalid_digest_length() {
    let keypair = SlhDsaSha2_128sKeypair::generate(&mut OsRng).expect("keygen failed");
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
fn slh_dsa_sha2_128s_prehash_ctx_length_boundary() {
    let keypair = SlhDsaSha2_128sKeypair::generate(&mut OsRng).expect("keygen failed");
    let digest = Sha256::digest(b"module bytes");

    let ctx_256 = vec![0x42u8; 256];
    let err = keypair
        .sign_prehash_deterministic(&ctx_256, PreHash::Sha256, &digest)
        .expect_err("sign_prehash_deterministic with 256-byte ctx must fail");
    assert_eq!(err, SigError::ContextTooLong { len: 256 });
}

#[test]
fn slh_dsa_sha2_128s_prehash_signature_does_not_verify_via_plain_verify_or_verify_ctx() {
    let keypair = SlhDsaSha2_128sKeypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();
    let ctx = b"8gentz-module-v1";
    let digest = Sha256::digest(b"module bytes");

    let prehash_sig = keypair
        .sign_prehash_deterministic(ctx, PreHash::Sha256, &digest)
        .expect("sign_prehash_deterministic failed");

    assert!(SlhDsaSha2_128sKeypair::verify(&pk, &digest, &prehash_sig).is_err());
    assert!(SlhDsaSha2_128sKeypair::verify_ctx(&pk, ctx, &digest, &prehash_sig).is_err());
    assert!(SlhDsaSha2_128sKeypair::verify_ctx(&pk, &[], &digest, &prehash_sig).is_err());
}

#[test]
fn slh_dsa_sha2_128s_prehash_domain_byte_differs_from_pure_ctx_signing() {
    // Structural proof: a signature produced by sign_ctx_deterministic(ctx, OID ||
    // digest) — pure mode, domain byte 0x00 — must NOT verify via verify_prehash
    // (domain byte 0x01).
    let keypair = SlhDsaSha2_128sKeypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();
    let ctx = b"8gentz-module-v1";
    let digest = Sha256::digest(b"module bytes");

    let oid = PreHash::Sha256.oid_der();
    let mut oid_and_digest = oid.to_vec();
    oid_and_digest.extend_from_slice(&digest);

    let pure_sig = keypair
        .sign_ctx_deterministic(ctx, &oid_and_digest)
        .expect("sign_ctx_deterministic failed");

    let err = SlhDsaSha2_128sKeypair::verify_prehash(&pk, ctx, PreHash::Sha256, &digest, &pure_sig)
        .expect_err("a pure-mode (0x00) signature must not verify as HashSLH-DSA (0x01)");
    assert_eq!(err, SigError::VerificationFailed);
}
