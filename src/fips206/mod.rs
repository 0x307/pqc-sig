//! FIPS 206 — FN-DSA (Falcon) Digital Signature Algorithm
//!
//! **This is a real, production-usable, tested implementation today** — native targets
//! only (C FFI via `pqcrypto-falcon`), gated behind the non-default `fndsa` feature. It is
//! **NOT compatible with `wasm32-unknown-unknown`**; use ML-DSA (FIPS 204) for WASM targets.
//! `fndsa` stays non-default on purpose (WASM-first ecosystem posture), not because the
//! implementation itself is provisional.
//!
//! Implements both parameter sets:
//! - [`FnDsa512Keypair`]  — Security Level 1, 897-byte public key, 666-byte signature
//! - [`FnDsa1024Keypair`] — Security Level 5, 1793-byte public key, 1280-byte signature
//!
//! All implementations use the `pqcrypto-falcon` crate (C FFI wrapper).
//!
//! # Multikey / DID Document encoding
//!
//! [`crate::types::SigPublicKey::to_multibase`]/`from_multibase` work for FN-DSA public
//! keys using a **provisional, `0x307`-reserved private-use multicodec code**
//! (`0x307000`/`0x307001`), since [multiformats/multicodec] has no registered code for
//! FN-DSA/Falcon upstream. See [`crate::types::FN_DSA_PRIVATE_USE_BASE`]'s doc comment for
//! the full rationale, interop scope (0x307-controlled systems, not generic third-party
//! multicodec decoders), and the revisit trigger for when/if upstream registers a real code.
//!
//! [multiformats/multicodec]: https://github.com/multiformats/multicodec

pub mod fn_dsa_512;
pub mod fn_dsa_1024;

pub use fn_dsa_512::FnDsa512Keypair;
pub use fn_dsa_1024::FnDsa1024Keypair;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fn_dsa_512_smoke() {
        let keypair = FnDsa512Keypair::generate().expect("keygen failed");
        let pk = keypair.public_key();
        let msg = b"test message for FN-DSA-512";
        let sig = keypair.sign(msg).expect("sign failed");
        FnDsa512Keypair::verify(&pk, msg, &sig).expect("verify failed");
    }

    #[test]
    fn fn_dsa_512_wrong_message_fails() {
        let keypair = FnDsa512Keypair::generate().expect("keygen failed");
        let pk = keypair.public_key();
        let sig = keypair.sign(b"correct message").expect("sign failed");
        assert!(FnDsa512Keypair::verify(&pk, b"wrong message", &sig).is_err());
    }

    #[test]
    fn fn_dsa_1024_smoke() {
        let keypair = FnDsa1024Keypair::generate().expect("keygen failed");
        let pk = keypair.public_key();
        let msg = b"test message for FN-DSA-1024";
        let sig = keypair.sign(msg).expect("sign failed");
        FnDsa1024Keypair::verify(&pk, msg, &sig).expect("verify failed");
    }

    #[test]
    fn fn_dsa_1024_wrong_message_fails() {
        let keypair = FnDsa1024Keypair::generate().expect("keygen failed");
        let pk = keypair.public_key();
        let sig = keypair.sign(b"correct message").expect("sign failed");
        assert!(FnDsa1024Keypair::verify(&pk, b"wrong message", &sig).is_err());
    }

    #[test]
    fn public_key_sizes() {
        let kp512  = FnDsa512Keypair::generate().expect("keygen failed");
        let kp1024 = FnDsa1024Keypair::generate().expect("keygen failed");
        assert_eq!(kp512.public_key().bytes.len(),  897,  "FN-DSA-512 public key must be 897 bytes");
        assert_eq!(kp1024.public_key().bytes.len(), 1793, "FN-DSA-1024 public key must be 1793 bytes");
    }
}
