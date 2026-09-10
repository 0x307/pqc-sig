//! SLH-DSA-SHA2-192f (NIST FIPS 205, Security Level 3, fast signing)
//!
//! Parameter sizes:
//! - Public key:    48 bytes  (N=24)
//! - Secret key:    96 bytes  (N=24)
//! - Signature:  35664 bytes

extern crate alloc;
use alloc::format;

use slh_dsa::{SigningKey, VerifyingKey, Sha2_192f};
use slh_dsa::signature::{Keypair, Signer, Verifier};
use rand_core::{CryptoRng, RngCore};

use crate::ctx::check_ctx;
use crate::error::{SigError, SigResult};
use crate::prehash::{check_prehash, frame_prehash, PreHash};
use crate::types::{SigAlgorithm, SigPublicKey, SigSecretKey, Signature};

/// SLH-DSA-SHA2-192f keypair (NIST FIPS 205, Security Level 3, fast signing).
pub struct SlhDsaSha2_192fKeypair {
    signing_key: SigningKey<Sha2_192f>,
}

impl SlhDsaSha2_192fKeypair {
    /// Security strength in bits (FIPS 205 §10.2.2 pre-hash collision-strength floor).
    pub const SECURITY_STRENGTH_BITS: u32 = 192;

    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> SigResult<Self> {
        let mut sk_seed = [0u8; 24];
        let mut sk_prf  = [0u8; 24];
        let mut pk_seed = [0u8; 24];
        rng.fill_bytes(&mut sk_seed);
        rng.fill_bytes(&mut sk_prf);
        rng.fill_bytes(&mut pk_seed);
        Ok(Self { signing_key: SigningKey::<Sha2_192f>::slh_keygen_internal(&sk_seed, &sk_prf, &pk_seed) })
    }
    pub fn public_key(&self) -> SigPublicKey {
        SigPublicKey::new(SigAlgorithm::SlhDsaSha2_192f, self.signing_key.verifying_key().to_bytes().to_vec())
    }
    pub fn secret_key(&self) -> SigSecretKey {
        SigSecretKey::new(SigAlgorithm::SlhDsaSha2_192f, self.signing_key.to_bytes().to_vec())
    }
    pub fn sign<R: CryptoRng + RngCore>(&self, rng: &mut R, message: &[u8]) -> SigResult<Signature> {
        // N=24 for SHA2-192 parameter sets.
        let mut opt_rand = [0u8; 24];
        rng.fill_bytes(&mut opt_rand);
        let sig = self.signing_key.try_sign_with_context(message, &[], Some(&opt_rand))
            .map_err(|e| SigError::Signing(format!("{:?}", e)))?;
        Ok(Signature::new(SigAlgorithm::SlhDsaSha2_192f, sig.to_bytes().to_vec()))
    }
    pub fn sign_deterministic(&self, message: &[u8]) -> SigResult<Signature> {
        let sig = self.signing_key.try_sign(message)
            .map_err(|e| SigError::Signing(format!("{:?}", e)))?;
        Ok(Signature::new(SigAlgorithm::SlhDsaSha2_192f, sig.to_bytes().to_vec()))
    }
    pub fn verify(public_key: &SigPublicKey, message: &[u8], signature: &Signature) -> SigResult<()> {
        if public_key.algorithm != SigAlgorithm::SlhDsaSha2_192f {
            return Err(SigError::InvalidPublicKey(format!("expected SLH-DSA-SHA2-192f key, got {:?}", public_key.algorithm)));
        }
        if signature.algorithm != SigAlgorithm::SlhDsaSha2_192f {
            return Err(SigError::InvalidSignature(format!("expected SLH-DSA-SHA2-192f signature, got {:?}", signature.algorithm)));
        }
        let vk = VerifyingKey::<Sha2_192f>::try_from(public_key.bytes.as_slice())
            .map_err(|e| SigError::InvalidPublicKey(format!("{:?}", e)))?;
        let sig = slh_dsa::Signature::<Sha2_192f>::try_from(signature.bytes.as_slice())
            .map_err(|e| SigError::InvalidSignature(format!("{:?}", e)))?;
        vk.verify(message, &sig).map_err(|_| SigError::VerificationFailed)
    }

    /// Sign with a domain-separation context string (FIPS 205 §10.2), randomized. See the
    /// crate-level "Domain separation" docs. `ctx` must be at most
    /// [`MAX_CONTEXT_LEN`](crate::MAX_CONTEXT_LEN) bytes.
    pub fn sign_ctx<R: CryptoRng + RngCore>(&self, rng: &mut R, ctx: &[u8], message: &[u8]) -> SigResult<Signature> {
        check_ctx(ctx)?;
        let mut opt_rand = [0u8; 24];
        rng.fill_bytes(&mut opt_rand);
        let sig = self.signing_key.try_sign_with_context(message, ctx, Some(&opt_rand))
            .map_err(|e| SigError::Signing(format!("{:?}", e)))?;
        Ok(Signature::new(SigAlgorithm::SlhDsaSha2_192f, sig.to_bytes().to_vec()))
    }

    /// Sign deterministically with a domain-separation context string. An empty `ctx`
    /// (`&[]`) produces a signature byte-identical to [`Self::sign_deterministic`].
    pub fn sign_ctx_deterministic(&self, ctx: &[u8], message: &[u8]) -> SigResult<Signature> {
        check_ctx(ctx)?;
        let sig = self.signing_key.try_sign_with_context(message, ctx, None)
            .map_err(|e| SigError::Signing(format!("{:?}", e)))?;
        Ok(Signature::new(SigAlgorithm::SlhDsaSha2_192f, sig.to_bytes().to_vec()))
    }

    /// Verify a signature made with [`Self::sign_ctx`]/[`Self::sign_ctx_deterministic`].
    /// An empty `ctx` (`&[]`) verifies signatures made by [`Self::sign`]/
    /// [`Self::sign_deterministic`] (and vice versa).
    pub fn verify_ctx(public_key: &SigPublicKey, ctx: &[u8], message: &[u8], signature: &Signature) -> SigResult<()> {
        check_ctx(ctx)?;
        if public_key.algorithm != SigAlgorithm::SlhDsaSha2_192f {
            return Err(SigError::InvalidPublicKey(format!("expected SLH-DSA-SHA2-192f key, got {:?}", public_key.algorithm)));
        }
        if signature.algorithm != SigAlgorithm::SlhDsaSha2_192f {
            return Err(SigError::InvalidSignature(format!("expected SLH-DSA-SHA2-192f signature, got {:?}", signature.algorithm)));
        }
        let vk = VerifyingKey::<Sha2_192f>::try_from(public_key.bytes.as_slice())
            .map_err(|e| SigError::InvalidPublicKey(format!("{:?}", e)))?;
        let sig = slh_dsa::Signature::<Sha2_192f>::try_from(signature.bytes.as_slice())
            .map_err(|e| SigError::InvalidSignature(format!("{:?}", e)))?;
        vk.try_verify_with_context(message, ctx, &sig).map_err(|_| SigError::VerificationFailed)
    }

    /// Sign a pre-computed digest using the `HashSLH-DSA` construction (FIPS 205
    /// §10.2.2, Algorithm 23), randomized. See the crate-level "Pre-hash signing" docs.
    pub fn sign_prehash<R: CryptoRng + RngCore>(
        &self,
        rng: &mut R,
        ctx: &[u8],
        hash: PreHash,
        digest: &[u8],
    ) -> SigResult<Signature> {
        check_ctx(ctx)?;
        check_prehash(hash, digest, Self::SECURITY_STRENGTH_BITS, "SLH-DSA-SHA2-192f")?;
        let m_prime = frame_prehash(ctx, hash, digest);
        let mut opt_rand = [0u8; 24];
        rng.fill_bytes(&mut opt_rand);
        let sig = self.signing_key.slh_sign_internal(&[m_prime.as_slice()], Some(&opt_rand));
        Ok(Signature::new(SigAlgorithm::SlhDsaSha2_192f, sig.to_bytes().to_vec()))
    }

    /// Sign a pre-computed digest deterministically using the `HashSLH-DSA`
    /// construction. See [`Self::sign_prehash`] for the framing and validation rules.
    pub fn sign_prehash_deterministic(
        &self,
        ctx: &[u8],
        hash: PreHash,
        digest: &[u8],
    ) -> SigResult<Signature> {
        check_ctx(ctx)?;
        check_prehash(hash, digest, Self::SECURITY_STRENGTH_BITS, "SLH-DSA-SHA2-192f")?;
        let m_prime = frame_prehash(ctx, hash, digest);
        let sig = self.signing_key.slh_sign_internal(&[m_prime.as_slice()], None);
        Ok(Signature::new(SigAlgorithm::SlhDsaSha2_192f, sig.to_bytes().to_vec()))
    }

    /// Verify a signature made with [`Self::sign_prehash`]/[`Self::sign_prehash_deterministic`].
    pub fn verify_prehash(
        public_key: &SigPublicKey,
        ctx: &[u8],
        hash: PreHash,
        digest: &[u8],
        signature: &Signature,
    ) -> SigResult<()> {
        check_ctx(ctx)?;
        check_prehash(hash, digest, Self::SECURITY_STRENGTH_BITS, "SLH-DSA-SHA2-192f")?;
        if public_key.algorithm != SigAlgorithm::SlhDsaSha2_192f {
            return Err(SigError::InvalidPublicKey(format!("expected SLH-DSA-SHA2-192f key, got {:?}", public_key.algorithm)));
        }
        if signature.algorithm != SigAlgorithm::SlhDsaSha2_192f {
            return Err(SigError::InvalidSignature(format!("expected SLH-DSA-SHA2-192f signature, got {:?}", signature.algorithm)));
        }
        let vk = VerifyingKey::<Sha2_192f>::try_from(public_key.bytes.as_slice())
            .map_err(|e| SigError::InvalidPublicKey(format!("{:?}", e)))?;
        let sig = slh_dsa::Signature::<Sha2_192f>::try_from(signature.bytes.as_slice())
            .map_err(|e| SigError::InvalidSignature(format!("{:?}", e)))?;
        let m_prime = frame_prehash(ctx, hash, digest);
        vk.slh_verify_internal(&[m_prime.as_slice()], &sig).map_err(|_| SigError::VerificationFailed)
    }

    pub fn from_secret_key_bytes(bytes: &[u8]) -> SigResult<Self> {
        let signing_key = SigningKey::<Sha2_192f>::try_from(bytes)
            .map_err(|e| SigError::InvalidSecretKey(format!("{:?}", e)))?;
        Ok(Self { signing_key })
    }
}
