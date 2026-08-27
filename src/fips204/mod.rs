//! FIPS 204 — ML-DSA (Module Lattice Digital Signature Algorithm)
//!
//! Implements all three parameter sets:
//! - [`MlDsa44Keypair`]  — Security Level 2, 1312-byte public key
//! - [`MlDsa65Keypair`]  — Security Level 3, 1952-byte public key  ← recommended
//! - [`MlDsa87Keypair`]  — Security Level 5, 2592-byte public key
//!
//! All implementations use the `ml-dsa` crate (RustCrypto), which is:
//! - Pure Rust (no C FFI)
//! - `no_std`-compatible with `alloc`
//! - Directly compilable to `wasm32-unknown-unknown`
//! - Implements NIST FIPS 204 exactly

pub mod ml_dsa_44;
pub mod ml_dsa_65;
pub mod ml_dsa_87;

pub use ml_dsa_44::MlDsa44Keypair;
pub use ml_dsa_65::MlDsa65Keypair;
pub use ml_dsa_87::MlDsa87Keypair;

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    // ── MlDsa44Keypair smoke tests ────────────────────────────────────────────

    #[test]
    fn ml_dsa_44_smoke() {
        let keypair = MlDsa44Keypair::generate(&mut OsRng).expect("keygen failed");
        let pk = keypair.public_key();
        let message = b"test message for ML-DSA-44";
        let sig = keypair.sign(&mut OsRng, message).expect("sign failed");
        MlDsa44Keypair::verify(&pk, message, &sig).expect("verify failed");
    }

    #[test]
    fn ml_dsa_44_wrong_message_fails() {
        let keypair = MlDsa44Keypair::generate(&mut OsRng).expect("keygen failed");
        let pk = keypair.public_key();
        let sig = keypair.sign(&mut OsRng, b"correct message").expect("sign failed");
        assert!(MlDsa44Keypair::verify(&pk, b"wrong message", &sig).is_err());
    }

    // ── MlDsa65Keypair smoke tests ────────────────────────────────────────────

    #[test]
    fn ml_dsa_65_smoke() {
        let keypair = MlDsa65Keypair::generate(&mut OsRng).expect("keygen failed");
        let pk = keypair.public_key();
        let message = b"test message for ML-DSA-65";
        let sig = keypair.sign(&mut OsRng, message).expect("sign failed");
        MlDsa65Keypair::verify(&pk, message, &sig).expect("verify failed");
    }

    #[test]
    fn ml_dsa_65_wrong_message_fails() {
        let keypair = MlDsa65Keypair::generate(&mut OsRng).expect("keygen failed");
        let pk = keypair.public_key();
        let sig = keypair.sign(&mut OsRng, b"correct message").expect("sign failed");
        assert!(MlDsa65Keypair::verify(&pk, b"wrong message", &sig).is_err());
    }

    // ── MlDsa87Keypair smoke tests ────────────────────────────────────────────

    #[test]
    fn ml_dsa_87_smoke() {
        let keypair = MlDsa87Keypair::generate(&mut OsRng).expect("keygen failed");
        let pk = keypair.public_key();
        let message = b"test message for ML-DSA-87";
        let sig = keypair.sign(&mut OsRng, message).expect("sign failed");
        MlDsa87Keypair::verify(&pk, message, &sig).expect("verify failed");
    }

    #[test]
    fn ml_dsa_87_wrong_message_fails() {
        let keypair = MlDsa87Keypair::generate(&mut OsRng).expect("keygen failed");
        let pk = keypair.public_key();
        let sig = keypair.sign(&mut OsRng, b"correct message").expect("sign failed");
        assert!(MlDsa87Keypair::verify(&pk, b"wrong message", &sig).is_err());
    }

    // ── Key size checks ───────────────────────────────────────────────────────

    #[test]
    fn public_key_sizes() {
        let kp44 = MlDsa44Keypair::generate(&mut OsRng).expect("keygen failed");
        let kp65 = MlDsa65Keypair::generate(&mut OsRng).expect("keygen failed");
        let kp87 = MlDsa87Keypair::generate(&mut OsRng).expect("keygen failed");

        assert_eq!(kp44.public_key().bytes.len(), 1312, "ML-DSA-44 public key must be 1312 bytes");
        assert_eq!(kp65.public_key().bytes.len(), 1952, "ML-DSA-65 public key must be 1952 bytes");
        assert_eq!(kp87.public_key().bytes.len(), 2592, "ML-DSA-87 public key must be 2592 bytes");
    }

    #[test]
    fn secret_key_sizes() {
        let kp44 = MlDsa44Keypair::generate(&mut OsRng).expect("keygen failed");
        let kp65 = MlDsa65Keypair::generate(&mut OsRng).expect("keygen failed");
        let kp87 = MlDsa87Keypair::generate(&mut OsRng).expect("keygen failed");

        // ML-DSA secret keys are serialized as 32-byte seeds (preferred serialization
        // per the ml-dsa crate). The full expanded key form is deprecated.
        assert_eq!(kp44.secret_key().bytes.len(), 32, "ML-DSA-44 secret key (seed) must be 32 bytes");
        assert_eq!(kp65.secret_key().bytes.len(), 32, "ML-DSA-65 secret key (seed) must be 32 bytes");
        assert_eq!(kp87.secret_key().bytes.len(), 32, "ML-DSA-87 secret key (seed) must be 32 bytes");
    }

    // ── Serialization round-trip ──────────────────────────────────────────────

    #[test]
    fn ml_dsa_65_base64url_roundtrip() {
        let keypair = MlDsa65Keypair::generate(&mut OsRng).expect("keygen failed");
        let pk = keypair.public_key();
        let encoded = pk.to_base64url();
        let decoded = crate::types::SigPublicKey::from_base64url(
            crate::types::SigAlgorithm::MlDsa65,
            &encoded,
        ).expect("decode failed");
        assert_eq!(pk.bytes, decoded.bytes);
    }
}
