//! FN-DSA-1024 / Falcon-1024 (NIST FIPS 206, Security Level 5)
//!
//! **NOT WASM-compatible** — uses C FFI via `pqcrypto-falcon`.
//! Use ML-DSA (FIPS 204) for WASM targets.
//!
//! Parameter sizes:
//! - Public key:  1793 bytes
//! - Secret key:  2305 bytes
//! - Signature:   1280 bytes (max; Falcon signatures are variable-length)

extern crate alloc;
use alloc::format;

use pqcrypto_falcon::falcon1024;
use pqcrypto_traits::sign::{
    DetachedSignature as DetachedSignatureTrait,
    PublicKey as PublicKeyTrait,
    SecretKey as SecretKeyTrait,
};

use crate::error::{SigError, SigResult};
use crate::types::{SigAlgorithm, SigPublicKey, SigSecretKey, Signature};

/// FN-DSA-1024 / Falcon-1024 keypair (NIST FIPS 206, Security Level 5).
///
/// **NOT WASM-compatible.** Requires the `fndsa` feature flag.
/// For WASM targets, use [`crate::fips204::MlDsa87Keypair`] instead.
///
/// Falcon signatures are variable-length (up to 1280 bytes for Falcon-1024).
pub struct FnDsa1024Keypair {
    public_key: falcon1024::PublicKey,
    secret_key: falcon1024::SecretKey,
}

impl FnDsa1024Keypair {
    /// Generate a new FN-DSA-1024 keypair using the system RNG.
    ///
    /// Note: `pqcrypto-falcon` uses its own internal RNG (not caller-provided).
    pub fn generate() -> SigResult<Self> {
        let (pk, sk) = falcon1024::keypair();
        Ok(Self { public_key: pk, secret_key: sk })
    }

    /// Returns the public (verifying) key.
    pub fn public_key(&self) -> SigPublicKey {
        SigPublicKey::new(SigAlgorithm::FnDsa1024, self.public_key.as_bytes().to_vec())
    }

    /// Returns the secret (signing) key.
    pub fn secret_key(&self) -> SigSecretKey {
        SigSecretKey::new(SigAlgorithm::FnDsa1024, self.secret_key.as_bytes().to_vec())
    }

    /// Sign a message using this keypair's secret key.
    ///
    /// Falcon signatures are variable-length (probabilistic signing).
    pub fn sign(&self, message: &[u8]) -> SigResult<Signature> {
        let sig = falcon1024::detached_sign(message, &self.secret_key);
        Ok(Signature::new(SigAlgorithm::FnDsa1024, sig.as_bytes().to_vec()))
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

        let pk = falcon1024::PublicKey::from_bytes(&public_key.bytes)
            .map_err(|e| SigError::InvalidPublicKey(format!("{:?}", e)))?;

        let sig = falcon1024::DetachedSignature::from_bytes(&signature.bytes)
            .map_err(|e| SigError::InvalidSignature(format!("{:?}", e)))?;

        falcon1024::verify_detached_signature(&sig, message, &pk)
            .map_err(|_| SigError::VerificationFailed)
    }

    /// Restore a keypair from raw public and secret key bytes.
    pub fn from_key_bytes(pk_bytes: &[u8], sk_bytes: &[u8]) -> SigResult<Self> {
        let public_key = falcon1024::PublicKey::from_bytes(pk_bytes)
            .map_err(|e| SigError::InvalidPublicKey(format!("{:?}", e)))?;
        let secret_key = falcon1024::SecretKey::from_bytes(sk_bytes)
            .map_err(|e| SigError::InvalidSecretKey(format!("{:?}", e)))?;
        Ok(Self { public_key, secret_key })
    }
}
