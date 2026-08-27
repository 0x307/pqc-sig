//! Integration tests for FN-DSA / Falcon (FIPS 206).
//!
//! Requires the `fndsa` feature flag. These tests use C FFI and are NOT
//! compatible with `wasm32-unknown-unknown`.

#[cfg(feature = "fndsa")]
mod fndsa_tests {
    use pqc_sig::fips206::{FnDsa512Keypair, FnDsa1024Keypair};
    use pqc_sig::types::SigAlgorithm;

    // ── FN-DSA-512 ────────────────────────────────────────────────────────────

    #[test]
    fn fn_dsa_512_keygen_sign_verify() {
        let keypair = FnDsa512Keypair::generate().expect("keygen failed");
        let pk = keypair.public_key();
        let message = b"Hello, FN-DSA-512!";
        let sig = keypair.sign(message).expect("sign failed");
        FnDsa512Keypair::verify(&pk, message, &sig).expect("verify failed");
    }

    #[test]
    fn fn_dsa_512_wrong_message_fails() {
        let keypair = FnDsa512Keypair::generate().expect("keygen failed");
        let pk = keypair.public_key();
        let sig = keypair.sign(b"correct").expect("sign failed");
        assert!(FnDsa512Keypair::verify(&pk, b"wrong", &sig).is_err());
    }

    #[test]
    fn fn_dsa_512_wrong_key_fails() {
        let kp1 = FnDsa512Keypair::generate().expect("keygen failed");
        let kp2 = FnDsa512Keypair::generate().expect("keygen failed");
        let sig = kp1.sign(b"message").expect("sign failed");
        assert!(FnDsa512Keypair::verify(&kp2.public_key(), b"message", &sig).is_err());
    }

    #[test]
    fn fn_dsa_512_public_key_size() {
        let keypair = FnDsa512Keypair::generate().expect("keygen failed");
        assert_eq!(keypair.public_key().bytes.len(), 897);
        assert_eq!(keypair.public_key().algorithm, SigAlgorithm::FnDsa512);
    }

    #[test]
    fn fn_dsa_512_secret_key_size() {
        let keypair = FnDsa512Keypair::generate().expect("keygen failed");
        assert_eq!(keypair.secret_key().bytes.len(), 1281);
    }

    #[test]
    fn fn_dsa_512_signature_max_size() {
        let keypair = FnDsa512Keypair::generate().expect("keygen failed");
        let sig = keypair.sign(b"test").expect("sign failed");
        // Falcon signatures are variable-length, max 666 bytes
        assert!(sig.bytes.len() <= 666, "signature too large: {} bytes", sig.bytes.len());
    }

    #[test]
    fn fn_dsa_512_restore_from_bytes() {
        let keypair = FnDsa512Keypair::generate().expect("keygen failed");
        let pk_bytes = keypair.public_key().bytes.clone();
        let sk_bytes = keypair.secret_key().bytes.clone();

        let restored = FnDsa512Keypair::from_key_bytes(&pk_bytes, &sk_bytes)
            .expect("restore failed");
        let message = b"restore test";
        let sig = restored.sign(message).expect("sign failed");
        FnDsa512Keypair::verify(&restored.public_key(), message, &sig).expect("verify failed");
    }

    #[test]
    fn fn_dsa_512_large_message() {
        let keypair = FnDsa512Keypair::generate().expect("keygen failed");
        let pk = keypair.public_key();
        let message = vec![0xABu8; 65536]; // 64 KB
        let sig = keypair.sign(&message).expect("sign failed");
        FnDsa512Keypair::verify(&pk, &message, &sig).expect("verify failed");
    }

    #[test]
    fn fn_dsa_512_empty_message() {
        let keypair = FnDsa512Keypair::generate().expect("keygen failed");
        let pk = keypair.public_key();
        let sig = keypair.sign(b"").expect("sign empty message failed");
        FnDsa512Keypair::verify(&pk, b"", &sig).expect("verify empty message failed");
    }

    // ── FN-DSA-1024 ───────────────────────────────────────────────────────────

    #[test]
    fn fn_dsa_1024_keygen_sign_verify() {
        let keypair = FnDsa1024Keypair::generate().expect("keygen failed");
        let pk = keypair.public_key();
        let message = b"Hello, FN-DSA-1024!";
        let sig = keypair.sign(message).expect("sign failed");
        FnDsa1024Keypair::verify(&pk, message, &sig).expect("verify failed");
    }

    #[test]
    fn fn_dsa_1024_wrong_message_fails() {
        let keypair = FnDsa1024Keypair::generate().expect("keygen failed");
        let pk = keypair.public_key();
        let sig = keypair.sign(b"correct").expect("sign failed");
        assert!(FnDsa1024Keypair::verify(&pk, b"wrong", &sig).is_err());
    }

    #[test]
    fn fn_dsa_1024_public_key_size() {
        let keypair = FnDsa1024Keypair::generate().expect("keygen failed");
        assert_eq!(keypair.public_key().bytes.len(), 1793);
        assert_eq!(keypair.public_key().algorithm, SigAlgorithm::FnDsa1024);
    }

    #[test]
    fn fn_dsa_1024_secret_key_size() {
        let keypair = FnDsa1024Keypair::generate().expect("keygen failed");
        assert_eq!(keypair.secret_key().bytes.len(), 2305);
    }

    #[test]
    fn fn_dsa_1024_signature_max_size() {
        let keypair = FnDsa1024Keypair::generate().expect("keygen failed");
        let sig = keypair.sign(b"test").expect("sign failed");
        // Falcon-1024 signatures are variable-length, max 1280 bytes
        assert!(sig.bytes.len() <= 1280, "signature too large: {} bytes", sig.bytes.len());
    }

    // ── Cross-algorithm rejection ─────────────────────────────────────────────

    #[test]
    fn fn_dsa_cross_algorithm_rejected() {
        let kp512  = FnDsa512Keypair::generate().expect("keygen failed");
        let kp1024 = FnDsa1024Keypair::generate().expect("keygen failed");
        let sig512 = kp512.sign(b"test").expect("sign failed");
        // FN-DSA-512 signature should be rejected by FN-DSA-1024 verifier
        assert!(FnDsa1024Keypair::verify(&kp1024.public_key(), b"test", &sig512).is_err());
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
