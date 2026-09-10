//! FN-DSA-512 / Falcon-512 (NIST FIPS 206, Security Level 1)
//!
//! Pure Rust via the `fn-dsa` crate — `no_std` + `alloc`, WASM-compatible.
//!
//! Parameter sizes:
//! - Public key:   897 bytes
//! - Secret key:  1345 bytes (this crate's encoded signing-key format; not the
//!   raw 1281-byte NIST secret-key size — implementation-defined, like the
//!   ML-DSA seed encoding above)
//! - Signature:    666 bytes (fixed-length, zero-padded)

extern crate alloc;
use alloc::{format, vec, vec::Vec};

use fn_dsa::{
    sign_key_size, vrfy_key_size, signature_size, FN_DSA_LOGN_512,
    KeyPairGenerator, KeyPairGenerator512,
    SigningKey, SigningKey512,
    VerifyingKey, VerifyingKey512,
    DomainContext, DOMAIN_NONE, HASH_ID_RAW,
    HASH_ID_SHA256, HASH_ID_SHA384, HASH_ID_SHA512,
    HASH_ID_SHA3_256, HASH_ID_SHA3_384, HASH_ID_SHA3_512,
    HASH_ID_SHAKE128, HASH_ID_SHAKE256,
};
use rand_core::{CryptoRng, RngCore};

use crate::ctx::check_ctx;
use crate::error::{SigError, SigResult};
use crate::prehash::{check_prehash, PreHash};
use crate::types::{SigAlgorithm, SigPublicKey, SigSecretKey, Signature};

/// FN-DSA-512 / Falcon-512 keypair (NIST FIPS 206, Security Level 1).
///
/// Requires the `fndsa` feature flag. Pure Rust, WASM-compatible.
pub struct FnDsa512Keypair {
    sign_key: Vec<u8>,
    vrfy_key: Vec<u8>,
}

impl FnDsa512Keypair {
    /// Security strength in bits (NIST L1). Used to enforce the same pre-hash
    /// collision-strength floor as FIPS 204/205 (FN-DSA's own pre-hash mode is
    /// native, but this crate applies the same rule for consistency).
    pub const SECURITY_STRENGTH_BITS: u32 = 128;

    /// Generate a new FN-DSA-512 keypair using the provided RNG.
    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> SigResult<Self> {
        let mut sign_key = vec![0u8; sign_key_size(FN_DSA_LOGN_512)];
        let mut vrfy_key = vec![0u8; vrfy_key_size(FN_DSA_LOGN_512)];
        let mut kg = KeyPairGenerator512::default();
        kg.keygen(FN_DSA_LOGN_512, rng, &mut sign_key, &mut vrfy_key);
        Ok(Self { sign_key, vrfy_key })
    }

    /// Returns the public (verifying) key.
    pub fn public_key(&self) -> SigPublicKey {
        SigPublicKey::new(SigAlgorithm::FnDsa512, self.vrfy_key.clone())
    }

    /// Returns the secret (signing) key.
    pub fn secret_key(&self) -> SigSecretKey {
        SigSecretKey::new(SigAlgorithm::FnDsa512, self.sign_key.clone())
    }

    /// Sign a message using this keypair's secret key.
    pub fn sign<R: CryptoRng + RngCore>(&self, rng: &mut R, message: &[u8]) -> SigResult<Signature> {
        let mut sk = SigningKey512::decode(&self.sign_key)
            .ok_or_else(|| SigError::InvalidSecretKey("malformed FN-DSA-512 signing key".into()))?;
        let mut sig = vec![0u8; signature_size(FN_DSA_LOGN_512)];
        sk.sign(rng, &DOMAIN_NONE, &HASH_ID_RAW, message, &mut sig)
            .ok_or_else(|| SigError::Signing("fn-dsa signing failed".into()))?;
        Ok(Signature::new(SigAlgorithm::FnDsa512, sig))
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

        let vk = VerifyingKey512::decode(&public_key.bytes)
            .ok_or_else(|| SigError::InvalidPublicKey("malformed FN-DSA-512 public key".into()))?;

        if vk.verify(&signature.bytes, &DOMAIN_NONE, &HASH_ID_RAW, message) {
            Ok(())
        } else {
            Err(SigError::VerificationFailed)
        }
    }

    /// Sign a message with a domain-separation context string (FIPS 206 draft).
    ///
    /// `ctx` binds the signature to a specific application or protocol so that a
    /// signature produced under one context cannot be replayed as valid under another
    /// — see the crate-level "Domain separation" docs. `ctx` must be at most
    /// [`MAX_CONTEXT_LEN`](crate::MAX_CONTEXT_LEN) bytes. FN-DSA has no deterministic
    /// signing variant (matching [`Self::sign`]), so there is no `sign_ctx_deterministic`.
    pub fn sign_ctx<R: CryptoRng + RngCore>(&self, rng: &mut R, ctx: &[u8], message: &[u8]) -> SigResult<Signature> {
        check_ctx(ctx)?;
        let mut sk = SigningKey512::decode(&self.sign_key)
            .ok_or_else(|| SigError::InvalidSecretKey("malformed FN-DSA-512 signing key".into()))?;
        let mut sig = vec![0u8; signature_size(FN_DSA_LOGN_512)];
        sk.sign(rng, &DomainContext(ctx), &HASH_ID_RAW, message, &mut sig)
            .ok_or_else(|| SigError::Signing("fn-dsa signing failed".into()))?;
        Ok(Signature::new(SigAlgorithm::FnDsa512, sig))
    }

    /// Verify a signature made with [`Self::sign_ctx`].
    ///
    /// `ctx` must match exactly what was used to sign. An empty `ctx` (`&[]`) verifies
    /// signatures made by [`Self::sign`] (and vice versa).
    pub fn verify_ctx(public_key: &SigPublicKey, ctx: &[u8], message: &[u8], signature: &Signature) -> SigResult<()> {
        check_ctx(ctx)?;
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

        let vk = VerifyingKey512::decode(&public_key.bytes)
            .ok_or_else(|| SigError::InvalidPublicKey("malformed FN-DSA-512 public key".into()))?;

        if vk.verify(&signature.bytes, &DomainContext(ctx), &HASH_ID_RAW, message) {
            Ok(())
        } else {
            Err(SigError::VerificationFailed)
        }
    }

    /// Sign a pre-computed digest using `fn-dsa`'s native pre-hashed mode (FIPS 206
    /// draft), randomized.
    ///
    /// `digest` is the output of hashing the actual message with `hash` — this crate
    /// never hashes on the caller's behalf (see the crate-level "Pre-hash signing"
    /// docs). Unlike ML-DSA/SLH-DSA, FN-DSA's pre-hash framing is performed entirely
    /// by the upstream `fn-dsa` crate via its `HashIdentifier`/`DomainContext`
    /// parameters — `digest` is passed straight through as `hv`.
    /// `hash.collision_strength_bits()` must be at least [`Self::SECURITY_STRENGTH_BITS`]
    /// or this returns [`SigError::PreHashTooWeak`]; `digest.len()` must equal
    /// `hash.digest_len()` or this returns [`SigError::InvalidDigestLength`]. `ctx`
    /// follows the same rules as [`Self::sign_ctx`]. FN-DSA has no deterministic
    /// signing variant, so there is no `sign_prehash_deterministic`.
    pub fn sign_prehash<R: CryptoRng + RngCore>(
        &self,
        rng: &mut R,
        ctx: &[u8],
        hash: PreHash,
        digest: &[u8],
    ) -> SigResult<Signature> {
        check_ctx(ctx)?;
        check_prehash(hash, digest, Self::SECURITY_STRENGTH_BITS, "FN-DSA-512")?;
        let hash_id = fn_dsa_hash_id(hash);
        let mut sk = SigningKey512::decode(&self.sign_key)
            .ok_or_else(|| SigError::InvalidSecretKey("malformed FN-DSA-512 signing key".into()))?;
        let mut sig = vec![0u8; signature_size(FN_DSA_LOGN_512)];
        sk.sign(rng, &DomainContext(ctx), hash_id, digest, &mut sig)
            .ok_or_else(|| SigError::Signing("fn-dsa signing failed".into()))?;
        Ok(Signature::new(SigAlgorithm::FnDsa512, sig))
    }

    /// Verify a signature made with [`Self::sign_prehash`].
    ///
    /// A pre-hash signature does **not** verify via [`Self::verify`]/[`Self::verify_ctx`]
    /// (and vice versa) — `fn-dsa` frames pre-hashed and raw messages differently.
    pub fn verify_prehash(
        public_key: &SigPublicKey,
        ctx: &[u8],
        hash: PreHash,
        digest: &[u8],
        signature: &Signature,
    ) -> SigResult<()> {
        check_ctx(ctx)?;
        check_prehash(hash, digest, Self::SECURITY_STRENGTH_BITS, "FN-DSA-512")?;
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

        let vk = VerifyingKey512::decode(&public_key.bytes)
            .ok_or_else(|| SigError::InvalidPublicKey("malformed FN-DSA-512 public key".into()))?;

        let hash_id = fn_dsa_hash_id(hash);
        if vk.verify(&signature.bytes, &DomainContext(ctx), hash_id, digest) {
            Ok(())
        } else {
            Err(SigError::VerificationFailed)
        }
    }

    /// Restore a keypair from raw public and secret key bytes.
    pub fn from_key_bytes(pk_bytes: &[u8], sk_bytes: &[u8]) -> SigResult<Self> {
        VerifyingKey512::decode(pk_bytes)
            .ok_or_else(|| SigError::InvalidPublicKey("malformed FN-DSA-512 public key".into()))?;
        SigningKey512::decode(sk_bytes)
            .ok_or_else(|| SigError::InvalidSecretKey("malformed FN-DSA-512 signing key".into()))?;
        Ok(Self { sign_key: sk_bytes.to_vec(), vrfy_key: pk_bytes.to_vec() })
    }
}

/// Map a [`PreHash`] to the corresponding `fn-dsa` `HashIdentifier` constant.
fn fn_dsa_hash_id(hash: PreHash) -> &'static fn_dsa::HashIdentifier<'static> {
    match hash {
        PreHash::Sha256 => &HASH_ID_SHA256,
        PreHash::Sha384 => &HASH_ID_SHA384,
        PreHash::Sha512 => &HASH_ID_SHA512,
        PreHash::Sha3_256 => &HASH_ID_SHA3_256,
        PreHash::Sha3_384 => &HASH_ID_SHA3_384,
        PreHash::Sha3_512 => &HASH_ID_SHA3_512,
        PreHash::Shake128 => &HASH_ID_SHAKE128,
        PreHash::Shake256 => &HASH_ID_SHAKE256,
    }
}
