//! FN-DSA-1024 / Falcon-1024 (NIST FIPS 206, Security Level 5)
//!
//! Pure Rust via the `fn-dsa` crate — `no_std` + `alloc`, WASM-compatible.
//!
//! Parameter sizes:
//! - Public key:  1793 bytes
//! - Secret key:  2369 bytes (this crate's encoded signing-key format; not the
//!   raw 2305-byte NIST secret-key size — implementation-defined, like the
//!   ML-DSA seed encoding above)
//! - Signature:   1280 bytes (fixed-length, zero-padded)

extern crate alloc;
use alloc::{format, vec, vec::Vec};

use fn_dsa::{
    sign_key_size, vrfy_key_size, signature_size, FN_DSA_LOGN_1024,
    KeyPairGenerator, KeyPairGenerator1024,
    SigningKey, SigningKey1024,
    VerifyingKey, VerifyingKey1024,
    DOMAIN_NONE, HASH_ID_RAW,
};
use rand_core::{CryptoRng, RngCore};

use crate::error::{SigError, SigResult};
use crate::types::{SigAlgorithm, SigPublicKey, SigSecretKey, Signature};

/// FN-DSA-1024 / Falcon-1024 keypair (NIST FIPS 206, Security Level 5).
///
/// Requires the `fndsa` feature flag. Pure Rust, WASM-compatible.
pub struct FnDsa1024Keypair {
    sign_key: Vec<u8>,
    vrfy_key: Vec<u8>,
}

impl FnDsa1024Keypair {
    /// Generate a new FN-DSA-1024 keypair using the provided RNG.
    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> SigResult<Self> {
        let mut sign_key = vec![0u8; sign_key_size(FN_DSA_LOGN_1024)];
        let mut vrfy_key = vec![0u8; vrfy_key_size(FN_DSA_LOGN_1024)];
        let mut kg = KeyPairGenerator1024::default();
        kg.keygen(FN_DSA_LOGN_1024, rng, &mut sign_key, &mut vrfy_key);
        Ok(Self { sign_key, vrfy_key })
    }

    /// Returns the public (verifying) key.
    pub fn public_key(&self) -> SigPublicKey {
        SigPublicKey::new(SigAlgorithm::FnDsa1024, self.vrfy_key.clone())
    }

    /// Returns the secret (signing) key.
    pub fn secret_key(&self) -> SigSecretKey {
        SigSecretKey::new(SigAlgorithm::FnDsa1024, self.sign_key.clone())
    }

    /// Sign a message using this keypair's secret key.
    pub fn sign<R: CryptoRng + RngCore>(&self, rng: &mut R, message: &[u8]) -> SigResult<Signature> {
        let mut sk = SigningKey1024::decode(&self.sign_key)
            .ok_or_else(|| SigError::InvalidSecretKey("malformed FN-DSA-1024 signing key".into()))?;
        let mut sig = vec![0u8; signature_size(FN_DSA_LOGN_1024)];
        sk.sign(rng, &DOMAIN_NONE, &HASH_ID_RAW, message, &mut sig)
            .ok_or_else(|| SigError::Signing("fn-dsa signing failed".into()))?;
        Ok(Signature::new(SigAlgorithm::FnDsa1024, sig))
    }

    /// Verify a signature over a message using the given public key.
    pub fn verify(public_key: &SigPublicKey, message: &[u8], signature: &Signature) -> SigResult<()> {
        if public_key.algorithm != SigAlgorithm::FnDsa1024 {
            return Err(SigError::InvalidPublicKey(
                format!("expected FN-DSA-1024 key, got {:?}", public_key.algorithm)
            ));
        }
        if signature.algorithm != SigAlgorithm::FnDsa1024 {
            return Err(SigError::InvalidSignature(
                format!("expected FN-DSA-1024 signature, got {:?}", signature.algorithm)
            ));
        }

        let vk = VerifyingKey1024::decode(&public_key.bytes)
            .ok_or_else(|| SigError::InvalidPublicKey("malformed FN-DSA-1024 public key".into()))?;

        if vk.verify(&signature.bytes, &DOMAIN_NONE, &HASH_ID_RAW, message) {
            Ok(())
        } else {
            Err(SigError::VerificationFailed)
        }
    }

    /// Restore a keypair from raw public and secret key bytes.
    pub fn from_key_bytes(pk_bytes: &[u8], sk_bytes: &[u8]) -> SigResult<Self> {
        VerifyingKey1024::decode(pk_bytes)
            .ok_or_else(|| SigError::InvalidPublicKey("malformed FN-DSA-1024 public key".into()))?;
        SigningKey1024::decode(sk_bytes)
            .ok_or_else(|| SigError::InvalidSecretKey("malformed FN-DSA-1024 signing key".into()))?;
        Ok(Self { sign_key: sk_bytes.to_vec(), vrfy_key: pk_bytes.to_vec() })
    }
}
