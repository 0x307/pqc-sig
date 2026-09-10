//! Integration tests for FN-DSA / Falcon (FIPS 206).
//!
//! Requires the `fndsa` feature flag. Pure Rust, WASM-compatible.

#[cfg(feature = "fndsa")]
mod fndsa_tests {
    use pqc_sig::fips206::{FnDsa512Keypair, FnDsa1024Keypair};
    use pqc_sig::prehash::PreHash;
    use pqc_sig::types::SigAlgorithm;
    use pqc_sig::SigError;
    use rand::rngs::OsRng;
    use sha2::{Digest, Sha256, Sha512};

    // ── FN-DSA-512 ────────────────────────────────────────────────────────────

    #[test]
    fn fn_dsa_512_keygen_sign_verify() {
        let keypair = FnDsa512Keypair::generate(&mut OsRng).expect("keygen failed");
        let pk = keypair.public_key();
        let message = b"Hello, FN-DSA-512!";
        let sig = keypair.sign(&mut OsRng, message).expect("sign failed");
        FnDsa512Keypair::verify(&pk, message, &sig).expect("verify failed");
    }

    #[test]
    fn fn_dsa_512_wrong_message_fails() {
        let keypair = FnDsa512Keypair::generate(&mut OsRng).expect("keygen failed");
        let pk = keypair.public_key();
        let sig = keypair.sign(&mut OsRng, b"correct").expect("sign failed");
        assert!(FnDsa512Keypair::verify(&pk, b"wrong", &sig).is_err());
    }

    #[test]
    fn fn_dsa_512_wrong_key_fails() {
        let kp1 = FnDsa512Keypair::generate(&mut OsRng).expect("keygen failed");
        let kp2 = FnDsa512Keypair::generate(&mut OsRng).expect("keygen failed");
        let sig = kp1.sign(&mut OsRng, b"message").expect("sign failed");
        assert!(FnDsa512Keypair::verify(&kp2.public_key(), b"message", &sig).is_err());
    }

    #[test]
    fn fn_dsa_512_public_key_size() {
        let keypair = FnDsa512Keypair::generate(&mut OsRng).expect("keygen failed");
        assert_eq!(keypair.public_key().bytes.len(), 897);
        assert_eq!(keypair.public_key().algorithm, SigAlgorithm::FnDsa512);
    }

    #[test]
    fn fn_dsa_512_secret_key_size() {
        let keypair = FnDsa512Keypair::generate(&mut OsRng).expect("keygen failed");
        assert_eq!(keypair.secret_key().bytes.len(), 1345);
    }

    #[test]
    fn fn_dsa_512_signature_size() {
        let keypair = FnDsa512Keypair::generate(&mut OsRng).expect("keygen failed");
        let sig = keypair.sign(&mut OsRng, b"test").expect("sign failed");
        // fn-dsa encodes signatures at a fixed, zero-padded length.
        assert_eq!(sig.bytes.len(), 666, "FN-DSA-512 signature must be 666 bytes");
    }

    #[test]
    fn fn_dsa_512_restore_from_bytes() {
        let keypair = FnDsa512Keypair::generate(&mut OsRng).expect("keygen failed");
        let pk_bytes = keypair.public_key().bytes.clone();
        let sk_bytes = keypair.secret_key().bytes.clone();

        let restored = FnDsa512Keypair::from_key_bytes(&pk_bytes, &sk_bytes)
            .expect("restore failed");
        let message = b"restore test";
        let sig = restored.sign(&mut OsRng, message).expect("sign failed");
        FnDsa512Keypair::verify(&restored.public_key(), message, &sig).expect("verify failed");
    }

    #[test]
    fn fn_dsa_512_large_message() {
        let keypair = FnDsa512Keypair::generate(&mut OsRng).expect("keygen failed");
        let pk = keypair.public_key();
        let message = vec![0xABu8; 65536]; // 64 KB
        let sig = keypair.sign(&mut OsRng, &message).expect("sign failed");
        FnDsa512Keypair::verify(&pk, &message, &sig).expect("verify failed");
    }

    #[test]
    fn fn_dsa_512_empty_message() {
        let keypair = FnDsa512Keypair::generate(&mut OsRng).expect("keygen failed");
        let pk = keypair.public_key();
        let sig = keypair.sign(&mut OsRng, b"").expect("sign empty message failed");
        FnDsa512Keypair::verify(&pk, b"", &sig).expect("verify empty message failed");
    }

    // ── FN-DSA-1024 ───────────────────────────────────────────────────────────

    #[test]
    fn fn_dsa_1024_keygen_sign_verify() {
        let keypair = FnDsa1024Keypair::generate(&mut OsRng).expect("keygen failed");
        let pk = keypair.public_key();
        let message = b"Hello, FN-DSA-1024!";
        let sig = keypair.sign(&mut OsRng, message).expect("sign failed");
        FnDsa1024Keypair::verify(&pk, message, &sig).expect("verify failed");
    }

    #[test]
    fn fn_dsa_1024_wrong_message_fails() {
        let keypair = FnDsa1024Keypair::generate(&mut OsRng).expect("keygen failed");
        let pk = keypair.public_key();
        let sig = keypair.sign(&mut OsRng, b"correct").expect("sign failed");
        assert!(FnDsa1024Keypair::verify(&pk, b"wrong", &sig).is_err());
    }

    #[test]
    fn fn_dsa_1024_public_key_size() {
        let keypair = FnDsa1024Keypair::generate(&mut OsRng).expect("keygen failed");
        assert_eq!(keypair.public_key().bytes.len(), 1793);
        assert_eq!(keypair.public_key().algorithm, SigAlgorithm::FnDsa1024);
    }

    #[test]
    fn fn_dsa_1024_secret_key_size() {
        let keypair = FnDsa1024Keypair::generate(&mut OsRng).expect("keygen failed");
        assert_eq!(keypair.secret_key().bytes.len(), 2369);
    }

    #[test]
    fn fn_dsa_1024_signature_size() {
        let keypair = FnDsa1024Keypair::generate(&mut OsRng).expect("keygen failed");
        let sig = keypair.sign(&mut OsRng, b"test").expect("sign failed");
        // fn-dsa encodes signatures at a fixed, zero-padded length.
        assert_eq!(sig.bytes.len(), 1280, "FN-DSA-1024 signature must be 1280 bytes");
    }

    // ── Cross-algorithm rejection ─────────────────────────────────────────────

    #[test]
    fn fn_dsa_cross_algorithm_rejected() {
        let kp512  = FnDsa512Keypair::generate(&mut OsRng).expect("keygen failed");
        let kp1024 = FnDsa1024Keypair::generate(&mut OsRng).expect("keygen failed");
        let sig512 = kp512.sign(&mut OsRng, b"test").expect("sign failed");
        // FN-DSA-512 signature should be rejected by FN-DSA-1024 verifier
        assert!(FnDsa1024Keypair::verify(&kp1024.public_key(), b"test", &sig512).is_err());
    }

    // ── Domain separation: sign_ctx / verify_ctx (S-1) ────────────────────────

    #[test]
    fn fn_dsa_512_sign_ctx_roundtrip_and_wrong_ctx_rejected() {
        let keypair = FnDsa512Keypair::generate(&mut OsRng).expect("keygen failed");
        let pk = keypair.public_key();
        let message = b"fn-dsa-512 ctx roundtrip";
        let sig = keypair
            .sign_ctx(&mut OsRng, b"8gentz-agent-v1", message)
            .expect("sign_ctx failed");
        FnDsa512Keypair::verify_ctx(&pk, b"8gentz-agent-v1", message, &sig)
            .expect("verify_ctx with matching ctx must succeed");

        let err = FnDsa512Keypair::verify_ctx(&pk, b"8gentz-fabric-v1", message, &sig)
            .expect_err("verify_ctx with wrong ctx must fail");
        assert_eq!(err, SigError::VerificationFailed);
    }

    #[test]
    fn fn_dsa_1024_sign_ctx_roundtrip_and_wrong_ctx_rejected() {
        let keypair = FnDsa1024Keypair::generate(&mut OsRng).expect("keygen failed");
        let pk = keypair.public_key();
        let message = b"fn-dsa-1024 ctx roundtrip";
        let sig = keypair
            .sign_ctx(&mut OsRng, b"8gentz-agent-v1", message)
            .expect("sign_ctx failed");
        FnDsa1024Keypair::verify_ctx(&pk, b"8gentz-agent-v1", message, &sig)
            .expect("verify_ctx with matching ctx must succeed");

        let err = FnDsa1024Keypair::verify_ctx(&pk, b"8gentz-fabric-v1", message, &sig)
            .expect_err("verify_ctx with wrong ctx must fail");
        assert_eq!(err, SigError::VerificationFailed);
    }

    #[test]
    fn fn_dsa_512_empty_ctx_interoperates_with_legacy_api() {
        let keypair = FnDsa512Keypair::generate(&mut OsRng).expect("keygen failed");
        let pk = keypair.public_key();
        let message = b"empty ctx interop";

        // sign_ctx(&[], m) must be verifiable via the legacy verify().
        let ctx_sig = keypair.sign_ctx(&mut OsRng, &[], message).expect("sign_ctx failed");
        FnDsa512Keypair::verify(&pk, message, &ctx_sig)
            .expect("legacy verify() must accept empty-ctx signature");

        // Legacy sign() must be verifiable via verify_ctx(pk, &[], ..).
        let legacy_sig = keypair.sign(&mut OsRng, message).expect("sign failed");
        FnDsa512Keypair::verify_ctx(&pk, &[], message, &legacy_sig)
            .expect("verify_ctx with empty ctx must accept legacy sign() signature");
    }

    #[test]
    fn fn_dsa_512_ctx_length_boundary() {
        let keypair = FnDsa512Keypair::generate(&mut OsRng).expect("keygen failed");
        let pk = keypair.public_key();
        let message = b"ctx length boundary";

        // Exactly 255 bytes must succeed.
        let ctx_255 = vec![0x42u8; 255];
        let sig = keypair
            .sign_ctx(&mut OsRng, &ctx_255, message)
            .expect("sign_ctx with 255-byte ctx must succeed");
        FnDsa512Keypair::verify_ctx(&pk, &ctx_255, message, &sig)
            .expect("verify_ctx with 255-byte ctx must succeed");

        // 256 bytes must fail with ContextTooLong on both sign and verify.
        let ctx_256 = vec![0x42u8; 256];
        let err = keypair
            .sign_ctx(&mut OsRng, &ctx_256, message)
            .expect_err("sign_ctx with 256-byte ctx must fail");
        assert_eq!(err, SigError::ContextTooLong { len: 256 });

        let err = FnDsa512Keypair::verify_ctx(&pk, &ctx_256, message, &sig)
            .expect_err("verify_ctx with 256-byte ctx must fail");
        assert_eq!(err, SigError::ContextTooLong { len: 256 });
    }

    // ── Pre-hash signing: sign_prehash / verify_prehash (S-4) ─────────────────

    #[test]
    fn fn_dsa_512_prehash_roundtrip() {
        let keypair = FnDsa512Keypair::generate(&mut OsRng).expect("keygen failed");
        let pk = keypair.public_key();
        let digest = Sha256::digest(b"module bytes for FN-DSA-512");
        let sig = keypair
            .sign_prehash(&mut OsRng, b"8gentz-module-v1", PreHash::Sha256, &digest)
            .expect("sign_prehash failed");
        FnDsa512Keypair::verify_prehash(&pk, b"8gentz-module-v1", PreHash::Sha256, &digest, &sig)
            .expect("verify_prehash failed");
    }

    #[test]
    fn fn_dsa_1024_prehash_roundtrip() {
        let keypair = FnDsa1024Keypair::generate(&mut OsRng).expect("keygen failed");
        let pk = keypair.public_key();
        let digest = Sha512::digest(b"module bytes for FN-DSA-1024");
        let sig = keypair
            .sign_prehash(&mut OsRng, b"8gentz-module-v1", PreHash::Sha512, &digest)
            .expect("sign_prehash failed");
        FnDsa1024Keypair::verify_prehash(&pk, b"8gentz-module-v1", PreHash::Sha512, &digest, &sig)
            .expect("verify_prehash failed");
    }

    #[test]
    fn fn_dsa_512_prehash_wrong_ctx_fails() {
        let keypair = FnDsa512Keypair::generate(&mut OsRng).expect("keygen failed");
        let pk = keypair.public_key();
        let digest = Sha256::digest(b"module bytes");
        let sig = keypair
            .sign_prehash(&mut OsRng, b"8gentz-agent-v1", PreHash::Sha256, &digest)
            .expect("sign_prehash failed");

        let err = FnDsa512Keypair::verify_prehash(&pk, b"8gentz-fabric-v1", PreHash::Sha256, &digest, &sig)
            .expect_err("verify_prehash with wrong ctx must fail");
        assert_eq!(err, SigError::VerificationFailed);
    }

    #[test]
    fn fn_dsa_512_prehash_tampered_digest_fails() {
        let keypair = FnDsa512Keypair::generate(&mut OsRng).expect("keygen failed");
        let pk = keypair.public_key();
        let digest = Sha256::digest(b"module bytes");
        let sig = keypair
            .sign_prehash(&mut OsRng, b"8gentz-module-v1", PreHash::Sha256, &digest)
            .expect("sign_prehash failed");

        let mut tampered = digest.to_vec();
        tampered[0] ^= 0xFF;
        let err = FnDsa512Keypair::verify_prehash(&pk, b"8gentz-module-v1", PreHash::Sha256, &tampered, &sig)
            .expect_err("verify_prehash with tampered digest must fail");
        assert_eq!(err, SigError::VerificationFailed);
    }

    #[test]
    fn fn_dsa_1024_prehash_strength_enforcement() {
        // SHA-256 (128 bits) is too weak for FN-DSA-1024 (256 bits, NIST L5).
        let keypair = FnDsa1024Keypair::generate(&mut OsRng).expect("keygen failed");
        let digest = Sha256::digest(b"module bytes");
        let err = keypair
            .sign_prehash(&mut OsRng, b"8gentz-module-v1", PreHash::Sha256, &digest)
            .expect_err("FN-DSA-1024 must reject SHA-256 prehash");
        assert_eq!(
            err,
            SigError::PreHashTooWeak { hash: "SHA-256", strength: 128, algorithm: "FN-DSA-1024", required: 256 }
        );

        // SHA-256 is sufficient for FN-DSA-512 (128 bits, NIST L1).
        let keypair512 = FnDsa512Keypair::generate(&mut OsRng).expect("keygen failed");
        keypair512
            .sign_prehash(&mut OsRng, b"8gentz-module-v1", PreHash::Sha256, &digest)
            .expect("FN-DSA-512 must accept SHA-256 prehash");
    }

    #[test]
    fn fn_dsa_512_prehash_invalid_digest_length() {
        let keypair = FnDsa512Keypair::generate(&mut OsRng).expect("keygen failed");
        let short_digest = [0u8; 31]; // SHA-256 wants 32 bytes
        let err = keypair
            .sign_prehash(&mut OsRng, b"8gentz-module-v1", PreHash::Sha256, &short_digest)
            .expect_err("31-byte digest must be rejected for SHA-256");
        assert_eq!(
            err,
            SigError::InvalidDigestLength { hash: "SHA-256", expected: 32, got: 31 }
        );
    }

    #[test]
    fn fn_dsa_512_prehash_ctx_length_boundary() {
        let keypair = FnDsa512Keypair::generate(&mut OsRng).expect("keygen failed");
        let digest = Sha256::digest(b"module bytes");

        let ctx_256 = vec![0x42u8; 256];
        let err = keypair
            .sign_prehash(&mut OsRng, &ctx_256, PreHash::Sha256, &digest)
            .expect_err("sign_prehash with 256-byte ctx must fail");
        assert_eq!(err, SigError::ContextTooLong { len: 256 });
    }

    #[test]
    fn fn_dsa_512_prehash_signature_does_not_verify_via_plain_verify_or_verify_ctx() {
        let keypair = FnDsa512Keypair::generate(&mut OsRng).expect("keygen failed");
        let pk = keypair.public_key();
        let ctx = b"8gentz-module-v1";
        let digest = Sha256::digest(b"module bytes");

        let prehash_sig = keypair
            .sign_prehash(&mut OsRng, ctx, PreHash::Sha256, &digest)
            .expect("sign_prehash failed");

        assert!(FnDsa512Keypair::verify(&pk, &digest, &prehash_sig).is_err());
        assert!(FnDsa512Keypair::verify_ctx(&pk, ctx, &digest, &prehash_sig).is_err());
        assert!(FnDsa512Keypair::verify_ctx(&pk, &[], &digest, &prehash_sig).is_err());
    }
}

// Placeholder test that always passes when fndsa feature is not enabled
#[cfg(not(feature = "fndsa"))]
#[test]
fn fn_dsa_not_available_without_feature() {
    // FN-DSA requires the `fndsa` feature flag.
    // Run with: cargo test --features fndsa
    println!("FN-DSA tests skipped (enable with --features fndsa)");
}
