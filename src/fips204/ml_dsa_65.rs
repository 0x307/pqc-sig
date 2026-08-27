//! ML-DSA-65 (NIST FIPS 204, Security Level 3) — Recommended Default
//!
//! Parameter sizes:
//! - Public key:  1952 bytes
//! - Secret key:    32 bytes (seed — preferred serialization)
//! - Signature:   3309 bytes

extern crate alloc;
use alloc::format;

use ml_dsa::{
    KeyExport, KeyInit, Keypair, MlDsa65, Seed, SigningKey, VerifyingKey,
    signature::{Signer, Verifier},
};
use rand_core::{CryptoRng, RngCore};

use crate::error::{SigError, SigResult};
use crate::types::{SigAlgorithm, SigPublicKey, SigSecretKey, Signature};

/// ML-DSA-65 keypair (NIST FIPS 204, Security Level 3) — **Recommended Default**.
///
/// Provides AES-192-equivalent security against both classical and quantum adversaries.
/// This is the recommended parameter set, providing the best balance of security and performance.
///
/// # Example
/// ```rust,no_run
/// use rand::rngs::OsRng;
/// use pqc_sig::fips204::MlDsa65Keypair;
///
/// let keypair = MlDsa65Keypair::generate(&mut OsRng).unwrap();
/// let pk = keypair.public_key();
///
/// let message = b"Hello, post-quantum world!";
/// let signature = keypair.sign(&mut OsRng, message).unwrap();
///
/// MlDsa65Keypair::verify(&pk, message, &signature).unwrap();
/// ```
pub struct MlDsa65Keypair {
    signing_key: SigningKey<MlDsa65>,
}

impl MlDsa65Keypair {
    /// Generate a new ML-DSA-65 keypair using the provided RNG.
    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> SigResult<Self> {
        let mut seed_bytes = [0u8; 32];
        rng.fill_bytes(&mut seed_bytes);
        let seed: Seed = seed_bytes.into();
        let signing_key = SigningKey::<MlDsa65>::new(&seed);
        Ok(Self { signing_key })
    }

    /// Returns the public (verifying) key.
    pub fn public_key(&self) -> SigPublicKey {
        let vk = self.signing_key.verifying_key();
        SigPublicKey::new(
            SigAlgorithm::MlDsa65,
            vk.to_bytes().to_vec(),
        )
    }

    /// Returns the secret (signing) key as a 32-byte seed.
    pub fn secret_key(&self) -> SigSecretKey {
        SigSecretKey::new(
            SigAlgorithm::MlDsa65,
            self.signing_key.to_bytes().to_vec(),
        )
    }

    /// Sign a message using this keypair's secret key.
    pub fn sign<R: CryptoRng + RngCore>(&self, rng: &mut R, message: &[u8]) -> SigResult<Signature> {
        let _ = rng;
        let sig = self.signing_key.try_sign(message)
            .map_err(|e| SigError::Signing(format!("{:?}", e)))?;
        Ok(Signature::new(SigAlgorithm::MlDsa65, sig.encode().to_vec()))
    }

    /// Sign a message deterministically (no RNG needed).
    pub fn sign_deterministic(&self, message: &[u8]) -> SigResult<Signature> {
        let sig = self.signing_key.try_sign(message)
            .map_err(|e| SigError::Signing(format!("{:?}", e)))?;
        Ok(Signature::new(SigAlgorithm::MlDsa65, sig.encode().to_vec()))
    }

    /// Verify a signature over a message using the given public key.
    pub fn verify(public_key: &SigPublicKey, message: &[u8], signature: &Signature) -> SigResult<()> {
        if public_key.algorithm != SigAlgorithm::MlDsa65 {
            return Err(SigError::InvalidPublicKey(
                format!("expected ML-DSA-65 key, got {:?}", public_key.algorithm)
            ));
        }
        if signature.algorithm != SigAlgorithm::MlDsa65 {
            return Err(SigError::InvalidSignature(
                format!("expected ML-DSA-65 signature, got {:?}", signature.algorithm)
            ));
        }

        let vk_bytes: &[u8] = &public_key.bytes;
        let vk_arr = ml_dsa::EncodedVerifyingKey::<MlDsa65>::try_from(vk_bytes)
            .map_err(|_| SigError::InvalidPublicKey(
                format!("ML-DSA-65 public key must be 1952 bytes, got {}", vk_bytes.len())
            ))?;
        let vk = VerifyingKey::<MlDsa65>::decode(&vk_arr);

        let sig = ml_dsa::Signature::<MlDsa65>::try_from(signature.bytes.as_slice())
            .map_err(|e| SigError::InvalidSignature(format!("{:?}", e)))?;

        vk.verify(message, &sig)
            .map_err(|_| SigError::VerificationFailed)
    }

    /// Restore a keypair from a 32-byte seed.
    pub fn from_secret_key_bytes(bytes: &[u8]) -> SigResult<Self> {
        let seed_arr: [u8; 32] = bytes.try_into()
            .map_err(|_| SigError::InvalidSecretKey(
                format!("ML-DSA-65 seed must be 32 bytes, got {}", bytes.len())
            ))?;
        let seed: Seed = seed_arr.into();
        let signing_key = SigningKey::<MlDsa65>::new(&seed);
        Ok(Self { signing_key })
    }
}
