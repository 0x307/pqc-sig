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

use crate::ctx::check_ctx;
use crate::error::{SigError, SigResult};
use crate::prehash::{check_prehash, frame_prehash, PreHash};
use crate::types::{SigAlgorithm, SigPublicKey, SigSecretKey, Signature};

/// SLH-DSA-SHA2-128s keypair (NIST FIPS 205, Security Level 1, small signatures).
pub struct SlhDsaSha2_128sKeypair {
    signing_key: SigningKey<Sha2_128s>,
}

impl SlhDsaSha2_128sKeypair {
    /// Security strength in bits (FIPS 205 §10.2.2 pre-hash collision-strength floor).
    pub const SECURITY_STRENGTH_BITS: u32 = 128;

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

    /// Sign a message with a domain-separation context string (FIPS 205 §10.2), randomized.
    ///
    /// `ctx` binds the signature to a specific application or protocol — see the
    /// crate-level "Domain separation" docs. Must be at most
    /// [`MAX_CONTEXT_LEN`](crate::MAX_CONTEXT_LEN) bytes.
    pub fn sign_ctx<R: CryptoRng + RngCore>(&self, rng: &mut R, ctx: &[u8], message: &[u8]) -> SigResult<Signature> {
        check_ctx(ctx)?;
        // N=16 for SHA2-128 parameter sets.
        let mut opt_rand = [0u8; 16];
        rng.fill_bytes(&mut opt_rand);
        let sig = self.signing_key.try_sign_with_context(message, ctx, Some(&opt_rand))
            .map_err(|e| SigError::Signing(format!("{:?}", e)))?;
        Ok(Signature::new(SigAlgorithm::SlhDsaSha2_128s, sig.to_bytes().to_vec()))
    }

    /// Sign a message deterministically with a domain-separation context string.
    ///
    /// See [`Self::sign_ctx`] for details on `ctx`. An empty `ctx` (`&[]`) produces a
    /// signature byte-identical to [`Self::sign_deterministic`].
    pub fn sign_ctx_deterministic(&self, ctx: &[u8], message: &[u8]) -> SigResult<Signature> {
        check_ctx(ctx)?;
        let sig = self.signing_key.try_sign_with_context(message, ctx, None)
            .map_err(|e| SigError::Signing(format!("{:?}", e)))?;
        Ok(Signature::new(SigAlgorithm::SlhDsaSha2_128s, sig.to_bytes().to_vec()))
    }

    /// Verify a signature made with [`Self::sign_ctx`]/[`Self::sign_ctx_deterministic`].
    ///
    /// `ctx` must match exactly what was used to sign. An empty `ctx` (`&[]`) verifies
    /// signatures made by [`Self::sign`]/[`Self::sign_deterministic`] (and vice versa).
    pub fn verify_ctx(public_key: &SigPublicKey, ctx: &[u8], message: &[u8], signature: &Signature) -> SigResult<()> {
        check_ctx(ctx)?;
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
        vk.try_verify_with_context(message, ctx, &sig).map_err(|_| SigError::VerificationFailed)
    }

    /// Sign a pre-computed digest using the `HashSLH-DSA` construction (FIPS 205
    /// §10.2.2, Algorithm 23), randomized.
    ///
    /// `digest` is the output of hashing the actual message with `hash` — this crate
    /// never hashes on the caller's behalf (see the crate-level "Pre-hash signing"
    /// docs). `hash.collision_strength_bits()` must be at least
    /// [`Self::SECURITY_STRENGTH_BITS`] or this returns [`SigError::PreHashTooWeak`];
    /// `digest.len()` must equal `hash.digest_len()` or this returns
    /// [`SigError::InvalidDigestLength`]. `ctx` follows the same rules as
    /// [`Self::sign_ctx`].
    ///
    /// This builds `M' = 0x01 ‖ len(ctx) ‖ ctx ‖ OID(hash) ‖ digest` and signs it via
    /// the upstream `slh-dsa` crate's `slh_sign_internal` — the literal FIPS 205
    /// `HashSLH-DSA.Sign` construction, byte-for-byte interoperable with any
    /// conformant verifier.
    pub fn sign_prehash<R: CryptoRng + RngCore>(
        &self,
        rng: &mut R,
        ctx: &[u8],
        hash: PreHash,
        digest: &[u8],
    ) -> SigResult<Signature> {
        check_ctx(ctx)?;
        check_prehash(hash, digest, Self::SECURITY_STRENGTH_BITS, "SLH-DSA-SHA2-128s")?;
        let m_prime = frame_prehash(ctx, hash, digest);
        // N=16 for SHA2-128 parameter sets.
        let mut opt_rand = [0u8; 16];
        rng.fill_bytes(&mut opt_rand);
        let sig = self.signing_key.slh_sign_internal(&[m_prime.as_slice()], Some(&opt_rand));
        Ok(Signature::new(SigAlgorithm::SlhDsaSha2_128s, sig.to_bytes().to_vec()))
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
        check_prehash(hash, digest, Self::SECURITY_STRENGTH_BITS, "SLH-DSA-SHA2-128s")?;
        let m_prime = frame_prehash(ctx, hash, digest);
        let sig = self.signing_key.slh_sign_internal(&[m_prime.as_slice()], None);
        Ok(Signature::new(SigAlgorithm::SlhDsaSha2_128s, sig.to_bytes().to_vec()))
    }

    /// Verify a signature made with [`Self::sign_prehash`]/[`Self::sign_prehash_deterministic`].
    ///
    /// A pre-hash signature does **not** verify via [`Self::verify`]/[`Self::verify_ctx`]
    /// (and vice versa) — the `0x01` domain byte in `M'` structurally separates
    /// `HashSLH-DSA` from pure-mode SLH-DSA, per FIPS 205 §10.2.2.
    pub fn verify_prehash(
        public_key: &SigPublicKey,
        ctx: &[u8],
        hash: PreHash,
        digest: &[u8],
        signature: &Signature,
    ) -> SigResult<()> {
        check_ctx(ctx)?;
        check_prehash(hash, digest, Self::SECURITY_STRENGTH_BITS, "SLH-DSA-SHA2-128s")?;
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
        let m_prime = frame_prehash(ctx, hash, digest);
        vk.slh_verify_internal(&[m_prime.as_slice()], &sig).map_err(|_| SigError::VerificationFailed)
    }

    /// Restore a keypair from raw secret key bytes.
    pub fn from_secret_key_bytes(bytes: &[u8]) -> SigResult<Self> {
        let signing_key = SigningKey::<Sha2_128s>::try_from(bytes)
            .map_err(|e| SigError::InvalidSecretKey(format!("{:?}", e)))?;
        Ok(Self { signing_key })
    }
}
