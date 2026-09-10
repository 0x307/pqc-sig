//! ML-DSA-87 (NIST FIPS 204, Security Level 5)
//!
//! Parameter sizes:
//! - Public key:  2592 bytes
//! - Secret key:    32 bytes (seed — preferred serialization)
//! - Signature:   4627 bytes

extern crate alloc;
use alloc::format;

use ml_dsa::{
    B32, KeyExport, KeyInit, Keypair, MlDsa87, Seed, SigningKey, VerifyingKey,
    signature::{Signer, Verifier},
};
use rand_core::{CryptoRng, RngCore};

use crate::ctx::check_ctx;
use crate::error::{SigError, SigResult};
use crate::prehash::{check_prehash, frame_prehash, PreHash};
use crate::types::{SigAlgorithm, SigPublicKey, SigSecretKey, Signature};

/// ML-DSA-87 keypair (NIST FIPS 204, Security Level 5).
///
/// Provides AES-256-equivalent security against both classical and quantum adversaries.
/// Use this for the highest security requirements.
///
/// # Example
/// ```rust,no_run
/// use rand::rngs::OsRng;
/// use pqc_sig::fips204::MlDsa87Keypair;
///
/// let keypair = MlDsa87Keypair::generate(&mut OsRng).unwrap();
/// let pk = keypair.public_key();
///
/// let message = b"Hello, post-quantum world!";
/// let signature = keypair.sign(&mut OsRng, message).unwrap();
///
/// MlDsa87Keypair::verify(&pk, message, &signature).unwrap();
/// ```
pub struct MlDsa87Keypair {
    signing_key: SigningKey<MlDsa87>,
}

impl MlDsa87Keypair {
    /// Security strength in bits (FIPS 204 §5.4 pre-hash collision-strength floor).
    ///
    /// [`Self::sign_prehash`]/[`Self::sign_prehash_deterministic`]/[`Self::verify_prehash`]
    /// reject any [`PreHash`] whose [`PreHash::collision_strength_bits`] is below this.
    pub const SECURITY_STRENGTH_BITS: u32 = 256;

    /// Generate a new ML-DSA-87 keypair using the provided RNG.
    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> SigResult<Self> {
        let mut seed_bytes = [0u8; 32];
        rng.fill_bytes(&mut seed_bytes);
        let seed: Seed = seed_bytes.into();
        let signing_key = SigningKey::<MlDsa87>::new(&seed);
        Ok(Self { signing_key })
    }

    /// Returns the public (verifying) key.
    pub fn public_key(&self) -> SigPublicKey {
        let vk = self.signing_key.verifying_key();
        SigPublicKey::new(
            SigAlgorithm::MlDsa87,
            vk.to_bytes().to_vec(),
        )
    }

    /// Returns the secret (signing) key as a 32-byte seed.
    pub fn secret_key(&self) -> SigSecretKey {
        SigSecretKey::new(
            SigAlgorithm::MlDsa87,
            self.signing_key.to_bytes().to_vec(),
        )
    }

    /// Sign a message using this keypair's secret key.
    pub fn sign<R: CryptoRng + RngCore>(&self, rng: &mut R, message: &[u8]) -> SigResult<Signature> {
        let _ = rng;
        let sig = self.signing_key.try_sign(message)
            .map_err(|e| SigError::Signing(format!("{:?}", e)))?;
        Ok(Signature::new(SigAlgorithm::MlDsa87, sig.encode().to_vec()))
    }

    /// Sign a message deterministically (no RNG needed).
    pub fn sign_deterministic(&self, message: &[u8]) -> SigResult<Signature> {
        let sig = self.signing_key.try_sign(message)
            .map_err(|e| SigError::Signing(format!("{:?}", e)))?;
        Ok(Signature::new(SigAlgorithm::MlDsa87, sig.encode().to_vec()))
    }

    /// Verify a signature over a message using the given public key.
    pub fn verify(public_key: &SigPublicKey, message: &[u8], signature: &Signature) -> SigResult<()> {
        if public_key.algorithm != SigAlgorithm::MlDsa87 {
            return Err(SigError::InvalidPublicKey(
                format!("expected ML-DSA-87 key, got {:?}", public_key.algorithm)
            ));
        }
        if signature.algorithm != SigAlgorithm::MlDsa87 {
            return Err(SigError::InvalidSignature(
                format!("expected ML-DSA-87 signature, got {:?}", signature.algorithm)
            ));
        }

        let vk_bytes: &[u8] = &public_key.bytes;
        let vk_arr = ml_dsa::EncodedVerifyingKey::<MlDsa87>::try_from(vk_bytes)
            .map_err(|_| SigError::InvalidPublicKey(
                format!("ML-DSA-87 public key must be 2592 bytes, got {}", vk_bytes.len())
            ))?;
        let vk = VerifyingKey::<MlDsa87>::decode(&vk_arr);

        let sig = ml_dsa::Signature::<MlDsa87>::try_from(signature.bytes.as_slice())
            .map_err(|e| SigError::InvalidSignature(format!("{:?}", e)))?;

        vk.verify(message, &sig)
            .map_err(|_| SigError::VerificationFailed)
    }

    /// Sign a message with a domain-separation context string (FIPS 204 §5.2).
    ///
    /// `ctx` binds the signature to a specific application or protocol so that a
    /// signature produced under one context cannot be replayed as valid under another
    /// — see the crate-level "Domain separation" docs. `ctx` must be at most
    /// [`MAX_CONTEXT_LEN`](crate::MAX_CONTEXT_LEN) bytes, or this returns
    /// [`SigError::ContextTooLong`].
    ///
    /// This mirrors [`Self::sign`]'s current behavior: signing is deterministic and
    /// `rng` is accepted only for API symmetry with the other parameter sets.
    // TODO(hedging): `rng` is unused because true randomized signing requires
    // `ExpandedSigningKey::sign_randomized`, which needs a `rand_core` 0.10
    // `TryCryptoRng` — incompatible with the `rand_core` 0.6 `CryptoRng + RngCore`
    // bound this crate accepts. See docs/GAP_VALIDATION.md §3 risks. Deterministic
    // ML-DSA is still secure per FIPS 204.
    pub fn sign_ctx<R: CryptoRng + RngCore>(&self, rng: &mut R, ctx: &[u8], message: &[u8]) -> SigResult<Signature> {
        let _ = rng;
        self.sign_ctx_deterministic(ctx, message)
    }

    /// Sign a message deterministically with a domain-separation context string.
    ///
    /// See [`Self::sign_ctx`] for details on `ctx`. An empty `ctx` (`&[]`) produces a
    /// signature byte-identical to [`Self::sign_deterministic`] — both are FIPS 204
    /// "pure" mode signing with the empty context string.
    pub fn sign_ctx_deterministic(&self, ctx: &[u8], message: &[u8]) -> SigResult<Signature> {
        check_ctx(ctx)?;
        let sig = self.signing_key.expanded_key().sign_deterministic(message, ctx)
            .map_err(|e| SigError::Signing(format!("{:?}", e)))?;
        Ok(Signature::new(SigAlgorithm::MlDsa87, sig.encode().to_vec()))
    }

    /// Verify a signature made with [`Self::sign_ctx`]/[`Self::sign_ctx_deterministic`].
    ///
    /// `ctx` must match exactly what was used to sign; a signature made under one
    /// context MUST NOT verify under another. An empty `ctx` (`&[]`) verifies
    /// signatures made by [`Self::sign`]/[`Self::sign_deterministic`] (and vice versa).
    pub fn verify_ctx(public_key: &SigPublicKey, ctx: &[u8], message: &[u8], signature: &Signature) -> SigResult<()> {
        check_ctx(ctx)?;
        if public_key.algorithm != SigAlgorithm::MlDsa87 {
            return Err(SigError::InvalidPublicKey(
                format!("expected ML-DSA-87 key, got {:?}", public_key.algorithm)
            ));
        }
        if signature.algorithm != SigAlgorithm::MlDsa87 {
            return Err(SigError::InvalidSignature(
                format!("expected ML-DSA-87 signature, got {:?}", signature.algorithm)
            ));
        }

        let vk_bytes: &[u8] = &public_key.bytes;
        let vk_arr = ml_dsa::EncodedVerifyingKey::<MlDsa87>::try_from(vk_bytes)
            .map_err(|_| SigError::InvalidPublicKey(
                format!("ML-DSA-87 public key must be 2592 bytes, got {}", vk_bytes.len())
            ))?;
        let vk = VerifyingKey::<MlDsa87>::decode(&vk_arr);

        let sig = ml_dsa::Signature::<MlDsa87>::try_from(signature.bytes.as_slice())
            .map_err(|e| SigError::InvalidSignature(format!("{:?}", e)))?;

        if vk.verify_with_context(message, ctx, &sig) {
            Ok(())
        } else {
            Err(SigError::VerificationFailed)
        }
    }

    /// Sign a pre-computed digest using the `HashML-DSA` construction (FIPS 204 §5.4,
    /// Algorithm 4), hedged.
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
    /// the upstream `ml-dsa` crate's `ML-DSA.Sign_internal` (Algorithm 7), reachable as
    /// `ExpandedSigningKey::sign_internal` — the literal FIPS 204 `HashML-DSA.Sign`
    /// construction, byte-for-byte interoperable with any conformant verifier.
    ///
    /// Unlike [`Self::sign`]/[`Self::sign_ctx`], `rng` is genuinely used here: it fills
    /// the `rnd` value that `sign_internal` takes directly, so this path is truly
    /// hedged (no `rand_core` 0.10 adapter needed).
    pub fn sign_prehash<R: CryptoRng + RngCore>(
        &self,
        rng: &mut R,
        ctx: &[u8],
        hash: PreHash,
        digest: &[u8],
    ) -> SigResult<Signature> {
        check_ctx(ctx)?;
        check_prehash(hash, digest, Self::SECURITY_STRENGTH_BITS, "ML-DSA-87")?;
        let m_prime = frame_prehash(ctx, hash, digest);
        let mut rnd_bytes = [0u8; 32];
        rng.fill_bytes(&mut rnd_bytes);
        let rnd: B32 = rnd_bytes.into();
        let sig = self.signing_key.expanded_key().sign_internal(&[m_prime.as_slice()], &rnd);
        Ok(Signature::new(SigAlgorithm::MlDsa87, sig.encode().to_vec()))
    }

    /// Sign a pre-computed digest deterministically using the `HashML-DSA`
    /// construction. See [`Self::sign_prehash`] for the framing and validation rules.
    pub fn sign_prehash_deterministic(
        &self,
        ctx: &[u8],
        hash: PreHash,
        digest: &[u8],
    ) -> SigResult<Signature> {
        check_ctx(ctx)?;
        check_prehash(hash, digest, Self::SECURITY_STRENGTH_BITS, "ML-DSA-87")?;
        let m_prime = frame_prehash(ctx, hash, digest);
        let rnd: B32 = [0u8; 32].into();
        let sig = self.signing_key.expanded_key().sign_internal(&[m_prime.as_slice()], &rnd);
        Ok(Signature::new(SigAlgorithm::MlDsa87, sig.encode().to_vec()))
    }

    /// Verify a signature made with [`Self::sign_prehash`]/[`Self::sign_prehash_deterministic`].
    ///
    /// A pre-hash signature does **not** verify via [`Self::verify`]/[`Self::verify_ctx`]
    /// (and vice versa) — the `0x01` domain byte in `M'` structurally separates
    /// `HashML-DSA` from pure-mode ML-DSA, per FIPS 204 §5.4.
    pub fn verify_prehash(
        public_key: &SigPublicKey,
        ctx: &[u8],
        hash: PreHash,
        digest: &[u8],
        signature: &Signature,
    ) -> SigResult<()> {
        check_ctx(ctx)?;
        check_prehash(hash, digest, Self::SECURITY_STRENGTH_BITS, "ML-DSA-87")?;
        if public_key.algorithm != SigAlgorithm::MlDsa87 {
            return Err(SigError::InvalidPublicKey(
                format!("expected ML-DSA-87 key, got {:?}", public_key.algorithm)
            ));
        }
        if signature.algorithm != SigAlgorithm::MlDsa87 {
            return Err(SigError::InvalidSignature(
                format!("expected ML-DSA-87 signature, got {:?}", signature.algorithm)
            ));
        }

        let vk_bytes: &[u8] = &public_key.bytes;
        let vk_arr = ml_dsa::EncodedVerifyingKey::<MlDsa87>::try_from(vk_bytes)
            .map_err(|_| SigError::InvalidPublicKey(
                format!("ML-DSA-87 public key must be 2592 bytes, got {}", vk_bytes.len())
            ))?;
        let vk = VerifyingKey::<MlDsa87>::decode(&vk_arr);

        let sig = ml_dsa::Signature::<MlDsa87>::try_from(signature.bytes.as_slice())
            .map_err(|e| SigError::InvalidSignature(format!("{:?}", e)))?;

        let m_prime = frame_prehash(ctx, hash, digest);
        if vk.verify_internal(&m_prime, &sig) {
            Ok(())
        } else {
            Err(SigError::VerificationFailed)
        }
    }

    /// Restore a keypair from a 32-byte seed.
    pub fn from_secret_key_bytes(bytes: &[u8]) -> SigResult<Self> {
        let seed_arr: [u8; 32] = bytes.try_into()
            .map_err(|_| SigError::InvalidSecretKey(
                format!("ML-DSA-87 seed must be 32 bytes, got {}", bytes.len())
            ))?;
        let seed: Seed = seed_arr.into();
        let signing_key = SigningKey::<MlDsa87>::new(&seed);
        Ok(Self { signing_key })
    }
}
