//! SLH-DSA-SHAKE-192f (NIST FIPS 205, Security Level 3, fast signing)
//!
//! Parameter sizes:
//! - Public key:    48 bytes  (N=24)
//! - Secret key:    96 bytes  (N=24)
//! - Signature:  35664 bytes

extern crate alloc;
use alloc::format;

use slh_dsa::{SigningKey, VerifyingKey, Shake192f};
use slh_dsa::signature::{Keypair, Signer, Verifier};
use rand_core::{CryptoRng, RngCore};

use crate::error::{SigError, SigResult};
use crate::types::{SigAlgorithm, SigPublicKey, SigSecretKey, Signature};

/// SLH-DSA-SHAKE-192f keypair (NIST FIPS 205, Security Level 3, fast signing).
pub struct SlhDsaShake192fKeypair {
    signing_key: SigningKey<Shake192f>,
}

impl SlhDsaShake192fKeypair {
    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> SigResult<Self> {
        let mut sk_seed = [0u8; 24];
        let mut sk_prf  = [0u8; 24];
        let mut pk_seed = [0u8; 24];
        rng.fill_bytes(&mut sk_seed);
        rng.fill_bytes(&mut sk_prf);
        rng.fill_bytes(&mut pk_seed);
        Ok(Self { signing_key: SigningKey::<Shake192f>::slh_keygen_internal(&sk_seed, &sk_prf, &pk_seed) })
    }
    pub fn public_key(&self) -> SigPublicKey {
        SigPublicKey::new(SigAlgorithm::SlhDsaShake192f, self.signing_key.verifying_key().to_bytes().to_vec())
    }
    pub fn secret_key(&self) -> SigSecretKey {
        SigSecretKey::new(SigAlgorithm::SlhDsaShake192f, self.signing_key.to_bytes().to_vec())
    }
    pub fn sign<R: CryptoRng + RngCore>(&self, rng: &mut R, message: &[u8]) -> SigResult<Signature> {
        // N=24 for SHAKE-192 parameter sets.
        let mut opt_rand = [0u8; 24];
        rng.fill_bytes(&mut opt_rand);
        let sig = self.signing_key.try_sign_with_context(message, &[], Some(&opt_rand))
            .map_err(|e| SigError::Signing(format!("{:?}", e)))?;
        Ok(Signature::new(SigAlgorithm::SlhDsaShake192f, sig.to_bytes().to_vec()))
    }
    pub fn sign_deterministic(&self, message: &[u8]) -> SigResult<Signature> {
        let sig = self.signing_key.try_sign(message)
            .map_err(|e| SigError::Signing(format!("{:?}", e)))?;
        Ok(Signature::new(SigAlgorithm::SlhDsaShake192f, sig.to_bytes().to_vec()))
    }
    pub fn verify(public_key: &SigPublicKey, message: &[u8], signature: &Signature) -> SigResult<()> {
        if public_key.algorithm != SigAlgorithm::SlhDsaShake192f {
            return Err(SigError::InvalidPublicKey(format!("expected SLH-DSA-SHAKE-192f key, got {:?}", public_key.algorithm)));
        }
        if signature.algorithm != SigAlgorithm::SlhDsaShake192f {
            return Err(SigError::InvalidSignature(format!("expected SLH-DSA-SHAKE-192f signature, got {:?}", signature.algorithm)));
        }
        let vk = VerifyingKey::<Shake192f>::try_from(public_key.bytes.as_slice())
            .map_err(|e| SigError::InvalidPublicKey(format!("{:?}", e)))?;
        let sig = slh_dsa::Signature::<Shake192f>::try_from(signature.bytes.as_slice())
            .map_err(|e| SigError::InvalidSignature(format!("{:?}", e)))?;
        vk.verify(message, &sig).map_err(|_| SigError::VerificationFailed)
    }
    pub fn from_secret_key_bytes(bytes: &[u8]) -> SigResult<Self> {
        let signing_key = SigningKey::<Shake192f>::try_from(bytes)
            .map_err(|e| SigError::InvalidSecretKey(format!("{:?}", e)))?;
        Ok(Self { signing_key })
    }
}
