//! FIPS 205 — SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)
//!
//! Implements all 12 parameter sets across two hash families (SHA2 and SHAKE)
//! and three security levels (128/192/256) with two performance modes (s=small, f=fast):
//!
//! SHA2 variants:
//! - [`SlhDsaSha2_128sKeypair`]  — Security Level 1, small signatures (7856 bytes)
//! - [`SlhDsaSha2_128fKeypair`]  — Security Level 1, fast signing (17088 bytes)
//! - [`SlhDsaSha2_192sKeypair`]  — Security Level 3, small signatures (16224 bytes)
//! - [`SlhDsaSha2_192fKeypair`]  — Security Level 3, fast signing (35664 bytes)
//! - [`SlhDsaSha2_256sKeypair`]  — Security Level 5, small signatures (29792 bytes)
//! - [`SlhDsaSha2_256fKeypair`]  — Security Level 5, fast signing (49856 bytes)
//!
//! SHAKE variants:
//! - [`SlhDsaShake128sKeypair`]  — Security Level 1, small signatures (7856 bytes)
//! - [`SlhDsaShake128fKeypair`]  — Security Level 1, fast signing (17088 bytes)
//! - [`SlhDsaShake192sKeypair`]  — Security Level 3, small signatures (16224 bytes)
//! - [`SlhDsaShake192fKeypair`]  — Security Level 3, fast signing (35664 bytes)
//! - [`SlhDsaShake256sKeypair`]  — Security Level 5, small signatures (29792 bytes)
//! - [`SlhDsaShake256fKeypair`]  — Security Level 5, fast signing (49856 bytes)
//!
//! All implementations use the `slh-dsa` crate (RustCrypto), which is:
//! - Pure Rust (no C FFI)
//! - `no_std`-compatible with `alloc`
//! - Directly compilable to `wasm32-unknown-unknown`
//! - Implements NIST FIPS 205 exactly

pub mod slh_dsa_sha2_128s;
pub mod slh_dsa_sha2_128f;
pub mod slh_dsa_sha2_192s;
pub mod slh_dsa_sha2_192f;
pub mod slh_dsa_sha2_256s;
pub mod slh_dsa_sha2_256f;
pub mod slh_dsa_shake_128s;
pub mod slh_dsa_shake_128f;
pub mod slh_dsa_shake_192s;
pub mod slh_dsa_shake_192f;
pub mod slh_dsa_shake_256s;
pub mod slh_dsa_shake_256f;

pub use slh_dsa_sha2_128s::SlhDsaSha2_128sKeypair;
pub use slh_dsa_sha2_128f::SlhDsaSha2_128fKeypair;
pub use slh_dsa_sha2_192s::SlhDsaSha2_192sKeypair;
pub use slh_dsa_sha2_192f::SlhDsaSha2_192fKeypair;
pub use slh_dsa_sha2_256s::SlhDsaSha2_256sKeypair;
pub use slh_dsa_sha2_256f::SlhDsaSha2_256fKeypair;
pub use slh_dsa_shake_128s::SlhDsaShake128sKeypair;
pub use slh_dsa_shake_128f::SlhDsaShake128fKeypair;
pub use slh_dsa_shake_192s::SlhDsaShake192sKeypair;
pub use slh_dsa_shake_192f::SlhDsaShake192fKeypair;
pub use slh_dsa_shake_256s::SlhDsaShake256sKeypair;
pub use slh_dsa_shake_256f::SlhDsaShake256fKeypair;

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    // ── SHA2 variants ─────────────────────────────────────────────────────────

    #[test]
    fn slh_dsa_sha2_128s_smoke() {
        let keypair = SlhDsaSha2_128sKeypair::generate(&mut OsRng).expect("keygen failed");
        let pk = keypair.public_key();
        let msg = b"test message for SLH-DSA-SHA2-128s";
        let sig = keypair.sign(&mut OsRng, msg).expect("sign failed");
        SlhDsaSha2_128sKeypair::verify(&pk, msg, &sig).expect("verify failed");
    }

    #[test]
    fn slh_dsa_sha2_128f_smoke() {
        let keypair = SlhDsaSha2_128fKeypair::generate(&mut OsRng).expect("keygen failed");
        let pk = keypair.public_key();
        let msg = b"test message for SLH-DSA-SHA2-128f";
        let sig = keypair.sign(&mut OsRng, msg).expect("sign failed");
        SlhDsaSha2_128fKeypair::verify(&pk, msg, &sig).expect("verify failed");
    }

    #[test]
    fn slh_dsa_sha2_192s_smoke() {
        let keypair = SlhDsaSha2_192sKeypair::generate(&mut OsRng).expect("keygen failed");
        let pk = keypair.public_key();
        let msg = b"test message for SLH-DSA-SHA2-192s";
        let sig = keypair.sign(&mut OsRng, msg).expect("sign failed");
        SlhDsaSha2_192sKeypair::verify(&pk, msg, &sig).expect("verify failed");
    }

    #[test]
    fn slh_dsa_sha2_192f_smoke() {
        let keypair = SlhDsaSha2_192fKeypair::generate(&mut OsRng).expect("keygen failed");
        let pk = keypair.public_key();
        let msg = b"test message for SLH-DSA-SHA2-192f";
        let sig = keypair.sign(&mut OsRng, msg).expect("sign failed");
        SlhDsaSha2_192fKeypair::verify(&pk, msg, &sig).expect("verify failed");
    }

    // ── SHAKE variants ────────────────────────────────────────────────────────

    #[test]
    fn slh_dsa_shake_128s_smoke() {
        let keypair = SlhDsaShake128sKeypair::generate(&mut OsRng).expect("keygen failed");
        let pk = keypair.public_key();
        let msg = b"test message for SLH-DSA-SHAKE-128s";
        let sig = keypair.sign(&mut OsRng, msg).expect("sign failed");
        SlhDsaShake128sKeypair::verify(&pk, msg, &sig).expect("verify failed");
    }

    #[test]
    fn slh_dsa_shake_128f_smoke() {
        let keypair = SlhDsaShake128fKeypair::generate(&mut OsRng).expect("keygen failed");
        let pk = keypair.public_key();
        let msg = b"test message for SLH-DSA-SHAKE-128f";
        let sig = keypair.sign(&mut OsRng, msg).expect("sign failed");
        SlhDsaShake128fKeypair::verify(&pk, msg, &sig).expect("verify failed");
    }

    // ── Wrong message fails ───────────────────────────────────────────────────

    #[test]
    fn slh_dsa_sha2_128s_wrong_message_fails() {
        let keypair = SlhDsaSha2_128sKeypair::generate(&mut OsRng).expect("keygen failed");
        let pk = keypair.public_key();
        let sig = keypair.sign(&mut OsRng, b"correct message").expect("sign failed");
        assert!(SlhDsaSha2_128sKeypair::verify(&pk, b"wrong message", &sig).is_err());
    }

    // ── Public key sizes ──────────────────────────────────────────────────────

    #[test]
    fn public_key_sizes() {
        let kp128s = SlhDsaSha2_128sKeypair::generate(&mut OsRng).expect("keygen failed");
        let kp192s = SlhDsaSha2_192sKeypair::generate(&mut OsRng).expect("keygen failed");
        let kp256s = SlhDsaSha2_256sKeypair::generate(&mut OsRng).expect("keygen failed");

        assert_eq!(kp128s.public_key().bytes.len(), 32, "SLH-DSA-SHA2-128s public key must be 32 bytes");
        assert_eq!(kp192s.public_key().bytes.len(), 48, "SLH-DSA-SHA2-192s public key must be 48 bytes");
        assert_eq!(kp256s.public_key().bytes.len(), 64, "SLH-DSA-SHA2-256s public key must be 64 bytes");
    }
}
