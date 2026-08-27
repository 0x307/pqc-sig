//! FN-DSA-512 / Falcon-512 (NIST FIPS 206, Security Level 1)
//!
//! **NOT WASM-compatible** — uses C FFI via `pqcrypto-falcon`.
//! Use ML-DSA (FIPS 204) for WASM targets.
//!
//! Parameter sizes:
//! - Public key:   897 bytes
//! - Secret key:  1281 bytes
//! - Signature:    666 bytes (max; Falcon signatures are variable-length)

extern crate alloc;
use alloc::format;

use pqcrypto_falcon::falcon512;
use pqcrypto_traits::sign::{
    DetachedSignature as DetachedSignatureTrait,
    PublicKey as PublicKeyTrait,
    SecretKey as SecretKeyTrait,
};

use crate::error::{SigError, SigResult};
use crate::types::{SigAlgorithm, SigPublicKey, SigSecretKey, Signature};

/// FN-DSA-512 / Falcon-512 keypair (NIST FIPS 206, Security Level 1).
///
/// **NOT WASM-compatible.** Requires the `fndsa` feature flag.
/// For WASM targets, use [`crate::fips204::MlDsa44Keypair`] instead.
///
/// Falcon signatures are variable-length (up to 666 bytes for Falcon-512).
pub struct FnDsa512Keypair {
    public_key: falcon512::PublicKey,
    secret_key: falcon512::SecretKey,
}

impl FnDsa512Keypair {
    /// Generate a new FN-DSA-512 keypair using the system RNG.
    ///
    /// Note: `pqcrypto-falcon` uses its own internal RNG (not caller-provided).
    pub fn generate() -> SigResult<Self> {
        let (pk, sk) = falcon512::keypair();
        Ok(Self { public_key: pk, secret_key: sk })
    }

    /// Returns the public (verifying) key.
    pub fn public_key(&self) -> SigPublicKey {
        SigPublicKey::new(SigAlgorithm::FnDsa512, self.public_key.as_bytes().to_vec())
    }

    /// Returns the secret (signing) key.
    pub fn secret_key(&self) -> SigSecretKey {
        SigSecretKey::new(SigAlgorithm::FnDsa512, self.secret_key.as_bytes().to_vec())
    }

    /// Sign a message using this keypair's secret key.
    ///
    /// Falcon signatures are variable-length (probabilistic signing).
    pub fn sign(&self, message: &[u8]) -> SigResult<Signature> {
        let sig = falcon512::detached_sign(message, &self.secret_key);
        Ok(Signature::new(SigAlgorithm::FnDsa512, sig.as_bytes().to_vec()))
    }

    /// Verify a signature over a message using the given public key.
    pub fn verify(public_key: &SigPublicKey, message: &[u8], signature: &Signature) -> SigResult<()> {
        if public_key.algorithm != SigAlgorithm::FnDsa512 {
            return Err(SigError::InvalidPublicKey(
                format!("expected FN-DSA-512 key, got {:?}", public_key.algorithm)
            ));
        }
        if signature.algorithm != SigAlgorithm::FnDsa512 {
            return Err(SigError::InvalidSignature(
                format!("expected FN-DSA-512 signature, got {:?}", signature.algorithm)
            ));
        }

        let pk = falcon512::PublicKey::from_bytes(&public_key.bytes)
            .map_err(|e| SigError::InvalidPublicKey(format!("{:?}", e)))?;

        let sig = falcon512::DetachedSignature::from_bytes(&signature.bytes)
            .map_err(|e| SigError::InvalidSignature(format!("{:?}", e)))?;

        falcon512::verify_detached_signature(&sig, message, &pk)
            .map_err(|_| SigError::VerificationFailed)
    }

    /// Restore a keypair from raw public and secret key bytes.
    pub fn from_key_bytes(pk_bytes: &[u8], sk_bytes: &[u8]) -> SigResult<Self> {
        let public_key = falcon512::PublicKey::from_bytes(pk_bytes)
            .map_err(|e| SigError::InvalidPublicKey(format!("{:?}", e)))?;
        let secret_key = falcon512::SecretKey::from_bytes(sk_bytes)
            .map_err(|e| SigError::InvalidSecretKey(format!("{:?}", e)))?;
        Ok(Self { public_key, secret_key })
    }
}
