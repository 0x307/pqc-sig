//! SLH-DSA-SHA2-128s (NIST FIPS 205, Security Level 1, small signatures)
//!
//! Parameter sizes:
//! - Public key:   32 bytes  (N=16, VkLen=2*N=32)
//! - Secret key:   64 bytes  (N=16, SkLen=4*N=64)
//! - Signature:  7856 bytes

extern crate alloc;
use alloc::format;

use slh_dsa::{SigningKey, VerifyingKey, Sha2_128s};
use slh_dsa::signature::{Keypair, Signer, Verifier};
use rand_core::{CryptoRng, RngCore};

use crate::error::{SigError, SigResult};
use crate::types::{SigAlgorithm, SigPublicKey, SigSecretKey, Signature};

/// SLH-DSA-SHA2-128s keypair (NIST FIPS 205, Security Level 1, small signatures).
pub struct SlhDsaSha2_128sKeypair {
    signing_key: SigningKey<Sha2_128s>,
}

impl SlhDsaSha2_128sKeypair {
    /// Generate a new keypair using the provided RNG.
    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> SigResult<Self> {
        // N=16 for SHA2-128 parameter sets
        let mut sk_seed = [0u8; 16];
        let mut sk_prf  = [0u8; 16];
        let mut pk_seed = [0u8; 16];
        rng.fill_bytes(&mut sk_seed);
        rng.fill_bytes(&mut sk_prf);
        rng.fill_bytes(&mut pk_seed);
        let signing_key = SigningKey::<Sha2_128s>::slh_keygen_internal(&sk_seed, &sk_prf, &pk_seed);
        Ok(Self { signing_key })
    }

    /// Returns the public (verifying) key.
    pub fn public_key(&self) -> SigPublicKey {
        SigPublicKey::new(SigAlgorithm::SlhDsaSha2_128s, self.signing_key.verifying_key().to_bytes().to_vec())
    }

    /// Returns the secret (signing) key.
    pub fn secret_key(&self) -> SigSecretKey {
        SigSecretKey::new(SigAlgorithm::SlhDsaSha2_128s, self.signing_key.to_bytes().to_vec())
    }

    /// Sign a message (randomized signing — uses RNG to produce non-deterministic signatures).
    ///
    /// Each call with the same message produces a different signature (randomized per FIPS 205).
    pub fn sign<R: CryptoRng + RngCore>(&self, rng: &mut R, message: &[u8]) -> SigResult<Signature> {
        // N=16 for SHA2-128 parameter sets. Bridge rand_core 0.6 → try_sign_with_context opt_rand.
        // Use try_sign_with_context (not slh_sign_internal) to include the FIPS 205 domain separator.
        let mut opt_rand = [0u8; 16];
        rng.fill_bytes(&mut opt_rand);
        let sig = self.signing_key.try_sign_with_context(message, &[], Some(&opt_rand))
            .map_err(|e| SigError::Signing(format!("{:?}", e)))?;
        Ok(Signature::new(SigAlgorithm::SlhDsaSha2_128s, sig.to_bytes().to_vec()))
    }

    /// Sign a message deterministically (same message always produces same signature).
    pub fn sign_deterministic(&self, message: &[u8]) -> SigResult<Signature> {
        let sig = self.signing_key.try_sign(message)
            .map_err(|e| SigError::Signing(format!("{:?}", e)))?;
        Ok(Signature::new(SigAlgorithm::SlhDsaSha2_128s, sig.to_bytes().to_vec()))
    }

    /// Verify a signature over a message using the given public key.
    pub fn verify(public_key: &SigPublicKey, message: &[u8], signature: &Signature) -> SigResult<()> {
        if public_key.algorithm != SigAlgorithm::SlhDsaSha2_128s {
            return Err(SigError::InvalidPublicKey(format!("expected SLH-DSA-SHA2-128s key, got {:?}", public_key.algorithm)));
        }
        if signature.algorithm != SigAlgorithm::SlhDsaSha2_128s {
            return Err(SigError::InvalidSignature(format!("expected SLH-DSA-SHA2-128s signature, got {:?}", signature.algorithm)));
        }
        let vk = VerifyingKey::<Sha2_128s>::try_from(public_key.bytes.as_slice())
            .map_err(|e| SigError::InvalidPublicKey(format!("{:?}", e)))?;
        let sig = slh_dsa::Signature::<Sha2_128s>::try_from(signature.bytes.as_slice())
            .map_err(|e| SigError::InvalidSignature(format!("{:?}", e)))?;
        vk.verify(message, &sig).map_err(|_| SigError::VerificationFailed)
    }

    /// Restore a keypair from raw secret key bytes.
    pub fn from_secret_key_bytes(bytes: &[u8]) -> SigResult<Self> {
        let signing_key = SigningKey::<Sha2_128s>::try_from(bytes)
            .map_err(|e| SigError::InvalidSecretKey(format!("{:?}", e)))?;
        Ok(Self { signing_key })
    }
}
