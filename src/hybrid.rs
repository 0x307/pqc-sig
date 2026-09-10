//! Hybrid classical + post-quantum signatures: Ed25519 + ML-DSA-65.
//!
//! Requires the `hybrid` feature flag. Composes a classical Ed25519 signature with
//! a post-quantum ML-DSA-65 signature: [`HybridSigner::sign`] produces both, and
//! [`HybridSigner::verify`] requires both to pass. An attacker must break both the
//! classical and the post-quantum primitive to forge a signature — the standard
//! posture for bridging classical deployments to PQC during migration.
//!
//! # Example
//! ```rust,no_run
//! use rand::rngs::OsRng;
//! use pqc_sig::hybrid::HybridSigner;
//!
//! let signer = HybridSigner::generate(&mut OsRng).unwrap();
//! let pk = signer.public_key();
//!
//! let message = b"Hello, hybrid world!";
//! let signature = signer.sign(message).unwrap();
//!
//! HybridSigner::verify(message, &signature, &pk).unwrap();
//! ```
//!
//! # Migrating an existing classical (Ed25519) identity
//!
//! [`HybridSigner::from_ed25519_secret`] wraps an *existing* Ed25519 signing key
//! (rather than generating a fresh one) and pairs it with a freshly generated
//! ML-DSA-65 half — the one-liner bridge for an agent/service that already has a
//! classical identity. [`HybridSigner::secret_key`]/[`HybridSigner::from_secret_key_bytes`]
//! round-trip both halves for persistence. See `examples/hybrid_bridge.rs` for a full
//! runnable walkthrough, and `docs/SAGP_NOTES.md` for migration/Wave-1 guidance.

extern crate alloc;
use alloc::{format, vec::Vec};

use ed25519_dalek::{
    Signature as Ed25519Signature, Signer, SigningKey as Ed25519SigningKey,
    Verifier, VerifyingKey as Ed25519VerifyingKey,
};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::ctx::check_ctx;
use crate::error::{SigError, SigResult};
use crate::fips204::MlDsa65Keypair;
use crate::types::{
    deserialize_bytes_base64url, serialize_bytes_base64url, SigAlgorithm, SigPublicKey, Signature,
};

/// Algorithm identifier for this hybrid combination.
pub const HYBRID_ALGORITHM: &str = "ed25519+ml_dsa_65";

/// Domain byte for the crate-defined Ed25519 context framing used by
/// [`HybridSigner::sign_ctx`]/[`HybridSigner::verify_ctx`].
///
/// **This is a crate-defined convention, not a FIPS or RFC 8032 standard.** Ed25519 has
/// no native context mechanism (the optional RFC 8032 `Ed25519ctx` variant is not
/// exposed by `ed25519-dalek` for pure Ed25519), so this crate frames the classical
/// half's input as `HYBRID_CTX_FRAME_DOMAIN ‖ u8(ctx.len()) ‖ ctx ‖ message` before
/// handing it to plain Ed25519 signing/verification. See [`HybridSigner::sign_ctx`] for
/// the full rationale.
pub const HYBRID_CTX_FRAME_DOMAIN: u8 = 0x00;

/// Build the crate-defined Ed25519 ctx-framing used by [`HybridSigner::sign_ctx`]/
/// [`HybridSigner::verify_ctx`]. Callers must validate `ctx.len() <=`
/// [`MAX_CONTEXT_LEN`](crate::MAX_CONTEXT_LEN) (via [`check_ctx`]) before calling this.
fn frame_classical_ctx(ctx: &[u8], message: &[u8]) -> Vec<u8> {
    let mut framed = Vec::with_capacity(2 + ctx.len() + message.len());
    framed.push(HYBRID_CTX_FRAME_DOMAIN);
    framed.push(ctx.len() as u8);
    framed.extend_from_slice(ctx);
    framed.extend_from_slice(message);
    framed
}

/// Combined Ed25519 + ML-DSA-65 public key.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HybridPublicKey {
    /// Ed25519 verifying key (32 bytes).
    #[serde(
        serialize_with   = "serialize_bytes_base64url",
        deserialize_with = "deserialize_bytes_base64url"
    )]
    pub classical: Vec<u8>,
    /// ML-DSA-65 public key (1952 bytes).
    #[serde(
        serialize_with   = "serialize_bytes_base64url",
        deserialize_with = "deserialize_bytes_base64url"
    )]
    pub pqc: Vec<u8>,
}

impl HybridPublicKey {
    /// Serialize to JSON string.
    pub fn to_json(&self) -> SigResult<alloc::string::String> {
        serde_json::to_string(self).map_err(|e| SigError::Serialization(format!("{}", e)))
    }

    /// Deserialize from JSON string.
    pub fn from_json(json: &str) -> SigResult<Self> {
        serde_json::from_str(json).map_err(|e| SigError::Serialization(format!("{}", e)))
    }
}

/// Combined Ed25519 + ML-DSA-65 signature.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HybridSignature {
    /// Ed25519 signature (64 bytes).
    #[serde(
        serialize_with   = "serialize_bytes_base64url",
        deserialize_with = "deserialize_bytes_base64url"
    )]
    pub classical: Vec<u8>,
    /// ML-DSA-65 signature (3309 bytes).
    #[serde(
        serialize_with   = "serialize_bytes_base64url",
        deserialize_with = "deserialize_bytes_base64url"
    )]
    pub pqc: Vec<u8>,
}

impl HybridSignature {
    /// Serialize to JSON string.
    pub fn to_json(&self) -> SigResult<alloc::string::String> {
        serde_json::to_string(self).map_err(|e| SigError::Serialization(format!("{}", e)))
    }

    /// Deserialize from JSON string.
    pub fn from_json(json: &str) -> SigResult<Self> {
        serde_json::from_str(json).map_err(|e| SigError::Serialization(format!("{}", e)))
    }
}

/// Combined Ed25519 + ML-DSA-65 secret key material, for persistence across restarts.
/// Zeroized on drop.
///
/// Returned by [`HybridSigner::secret_key`]; round-trips through
/// [`HybridSigner::from_secret_key_bytes`]:
/// `HybridSigner::from_secret_key_bytes(&sk.ed25519_seed, &sk.ml_dsa_65)` reproduces a
/// signer with an identical [`HybridSigner::public_key`].
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct HybridSecretKey {
    /// Ed25519 signing key seed (32 bytes).
    pub ed25519_seed: [u8; 32],
    /// ML-DSA-65 secret key seed (32 bytes) — see [`MlDsa65Keypair::from_secret_key_bytes`].
    pub ml_dsa_65: Vec<u8>,
}

impl core::fmt::Debug for HybridSecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "HybridSecretKey {{ ed25519_seed: [REDACTED 32 bytes], ml_dsa_65: [REDACTED {} bytes] }}",
            self.ml_dsa_65.len()
        )
    }
}

/// Hybrid signer: Ed25519 (classical) + ML-DSA-65 (PQC, FIPS 204).
///
/// Both signatures are produced on [`sign`](Self::sign); [`verify`](Self::verify)
/// requires both to pass.
pub struct HybridSigner {
    ed25519_key: Ed25519SigningKey,
    ml_dsa_key: MlDsa65Keypair,
}

impl HybridSigner {
    /// Generate a new hybrid keypair (Ed25519 + ML-DSA-65) using the provided RNG.
    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> SigResult<Self> {
        let ed25519_key = Ed25519SigningKey::generate(rng);
        let ml_dsa_key = MlDsa65Keypair::generate(rng)?;
        Ok(Self { ed25519_key, ml_dsa_key })
    }

    /// Bridge an *existing* Ed25519 identity into a hybrid signer: keeps the classical
    /// key exactly as-is (a legacy agent's already-deployed key) and generates a fresh
    /// ML-DSA-65 half. This is the one-liner migration path for agents moving from a
    /// pure-classical identity to the hybrid scheme — see `examples/hybrid_bridge.rs`.
    ///
    /// The resulting signer's classical public key equals the Ed25519 verifying key
    /// derived from `ed25519_secret`, so existing peers can still recognise the agent.
    pub fn from_ed25519_secret<R: CryptoRng + RngCore>(
        rng: &mut R,
        ed25519_secret: &[u8; 32],
    ) -> SigResult<Self> {
        let ed25519_key = Ed25519SigningKey::from_bytes(ed25519_secret);
        let ml_dsa_key = MlDsa65Keypair::generate(rng)?;
        Ok(Self { ed25519_key, ml_dsa_key })
    }

    /// Restore a hybrid signer from persisted secret key material.
    ///
    /// `ed25519_secret` is the raw 32-byte Ed25519 signing key seed (as returned by
    /// [`HybridSecretKey::ed25519_seed`] / `ed25519_dalek::SigningKey::to_bytes`).
    /// `ml_dsa_65_seed` is the ML-DSA-65 secret key seed and must be **exactly 32
    /// bytes** (see [`MlDsa65Keypair::from_secret_key_bytes`]) — this is the same
    /// encoding [`HybridSecretKey::ml_dsa_65`] / [`MlDsa65Keypair::secret_key`]
    /// produce, not the fully expanded ML-DSA signing key. Returns
    /// [`SigError::InvalidSecretKey`] if `ml_dsa_65_seed` is not 32 bytes.
    pub fn from_secret_key_bytes(
        ed25519_secret: &[u8; 32],
        ml_dsa_65_seed: &[u8],
    ) -> SigResult<Self> {
        let ed25519_key = Ed25519SigningKey::from_bytes(ed25519_secret);
        let ml_dsa_key = MlDsa65Keypair::from_secret_key_bytes(ml_dsa_65_seed)?;
        Ok(Self { ed25519_key, ml_dsa_key })
    }

    /// Export both secret-key halves for persistence. See [`HybridSecretKey`] for the
    /// round-trip guarantee via [`Self::from_secret_key_bytes`].
    pub fn secret_key(&self) -> HybridSecretKey {
        HybridSecretKey {
            ed25519_seed: self.ed25519_key.to_bytes(),
            ml_dsa_65: self.ml_dsa_key.secret_key().bytes.clone(),
        }
    }

    /// Returns the combined public key.
    pub fn public_key(&self) -> HybridPublicKey {
        HybridPublicKey {
            classical: self.ed25519_key.verifying_key().to_bytes().to_vec(),
            pqc: self.ml_dsa_key.public_key().bytes,
        }
    }

    /// Sign a message, producing both an Ed25519 and an ML-DSA-65 signature.
    pub fn sign(&self, message: &[u8]) -> SigResult<HybridSignature> {
        let classical = self.ed25519_key.sign(message).to_bytes().to_vec();
        let pqc = self.ml_dsa_key.sign_deterministic(message)?.bytes;
        Ok(HybridSignature { classical, pqc })
    }

    /// Verify a hybrid signature — both the Ed25519 and the ML-DSA-65 signature
    /// must pass. Fails closed: if either check fails, verification fails.
    pub fn verify(message: &[u8], signature: &HybridSignature, public_key: &HybridPublicKey) -> SigResult<()> {
        // Classical (Ed25519) side.
        let vk_bytes: [u8; 32] = public_key.classical.as_slice().try_into().map_err(|_| {
            SigError::InvalidPublicKey(format!(
                "Ed25519 public key must be 32 bytes, got {}",
                public_key.classical.len()
            ))
        })?;
        let ed25519_vk = Ed25519VerifyingKey::from_bytes(&vk_bytes)
            .map_err(|e| SigError::InvalidPublicKey(format!("{}", e)))?;

        let sig_bytes: [u8; 64] = signature.classical.as_slice().try_into().map_err(|_| {
            SigError::InvalidSignature(format!(
                "Ed25519 signature must be 64 bytes, got {}",
                signature.classical.len()
            ))
        })?;
        let ed25519_sig = Ed25519Signature::from_bytes(&sig_bytes);

        ed25519_vk
            .verify(message, &ed25519_sig)
            .map_err(|_| SigError::HybridClassicalFailed)?;

        // Post-quantum (ML-DSA-65) side.
        let pqc_pk = SigPublicKey::new(SigAlgorithm::MlDsa65, public_key.pqc.clone());
        let pqc_sig = Signature::new(SigAlgorithm::MlDsa65, signature.pqc.clone());
        MlDsa65Keypair::verify(&pqc_pk, message, &pqc_sig).map_err(|_| SigError::HybridPqcFailed)?;

        Ok(())
    }

    /// Sign a message with a domain-separation context string (S-1 parity for hybrid
    /// signers).
    ///
    /// The ML-DSA-65 half uses the native FIPS 204 §5.2 `ctx` mechanism via
    /// [`MlDsa65Keypair::sign_ctx_deterministic`]. Ed25519 (RFC 8032) has no `ctx`
    /// parameter of its own — pure Ed25519 as exposed by `ed25519-dalek` does not
    /// implement the optional `Ed25519ctx` variant — so the classical half instead
    /// signs a **crate-defined** framed message (not a FIPS or RFC standard; see
    /// [`HYBRID_CTX_FRAME_DOMAIN`]): `HYBRID_CTX_FRAME_DOMAIN ‖ u8(ctx.len()) ‖ ctx ‖
    /// message`. This binds the classical signature to `ctx` so a stripped classical
    /// half cannot be replayed as a plain Ed25519 signature over `message` under a
    /// different (or absent) context.
    ///
    /// Because of this framing, **`sign_ctx(rng, &[], m)` is NOT byte-identical to
    /// [`Self::sign`]`(m)`** on the classical half — unlike the pure-FIPS `sign_ctx`
    /// methods elsewhere in this crate, where an empty `ctx` is byte-identical to the
    /// non-`ctx` API. The two constructions are distinct and not interchangeable:
    /// [`Self::verify_ctx`]`(pk, &[], m, sig)` rejects a signature made by
    /// [`Self::sign`], and [`Self::verify`] rejects a signature made by `sign_ctx`
    /// (mode separation).
    ///
    /// `rng` is accepted for API symmetry with this crate's other `sign_ctx` methods;
    /// both halves are deterministic here (Ed25519 by construction, and the ML-DSA-65
    /// half via [`MlDsa65Keypair::sign_ctx_deterministic`]), so `rng` is unused. `ctx`
    /// must be at most [`MAX_CONTEXT_LEN`](crate::MAX_CONTEXT_LEN) bytes, or this
    /// returns [`SigError::ContextTooLong`].
    pub fn sign_ctx<R: CryptoRng + RngCore>(
        &self,
        rng: &mut R,
        ctx: &[u8],
        message: &[u8],
    ) -> SigResult<HybridSignature> {
        let _ = rng;
        check_ctx(ctx)?;
        let framed = frame_classical_ctx(ctx, message);
        let classical = self.ed25519_key.sign(&framed).to_bytes().to_vec();
        let pqc = self.ml_dsa_key.sign_ctx_deterministic(ctx, message)?.bytes;
        Ok(HybridSignature { classical, pqc })
    }

    /// Verify a signature made with [`Self::sign_ctx`] — both the Ed25519 (over the
    /// `ctx`-framed message, see [`Self::sign_ctx`]) and the ML-DSA-65 (native FIPS
    /// `ctx`) checks must pass. `ctx` must match exactly what was used to sign; fails
    /// closed like [`Self::verify`].
    pub fn verify_ctx(
        public_key: &HybridPublicKey,
        ctx: &[u8],
        message: &[u8],
        signature: &HybridSignature,
    ) -> SigResult<()> {
        check_ctx(ctx)?;

        // Classical (Ed25519) side, over the ctx-framed message.
        let vk_bytes: [u8; 32] = public_key.classical.as_slice().try_into().map_err(|_| {
            SigError::InvalidPublicKey(format!(
                "Ed25519 public key must be 32 bytes, got {}",
                public_key.classical.len()
            ))
        })?;
        let ed25519_vk = Ed25519VerifyingKey::from_bytes(&vk_bytes)
            .map_err(|e| SigError::InvalidPublicKey(format!("{}", e)))?;

        let sig_bytes: [u8; 64] = signature.classical.as_slice().try_into().map_err(|_| {
            SigError::InvalidSignature(format!(
                "Ed25519 signature must be 64 bytes, got {}",
                signature.classical.len()
            ))
        })?;
        let ed25519_sig = Ed25519Signature::from_bytes(&sig_bytes);

        let framed = frame_classical_ctx(ctx, message);
        ed25519_vk
            .verify(&framed, &ed25519_sig)
            .map_err(|_| SigError::HybridClassicalFailed)?;

        // Post-quantum (ML-DSA-65) side, native FIPS ctx.
        let pqc_pk = SigPublicKey::new(SigAlgorithm::MlDsa65, public_key.pqc.clone());
        let pqc_sig = Signature::new(SigAlgorithm::MlDsa65, signature.pqc.clone());
        MlDsa65Keypair::verify_ctx(&pqc_pk, ctx, message, &pqc_sig)
            .map_err(|_| SigError::HybridPqcFailed)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use rand::rngs::OsRng;

    #[test]
    fn both_pass() {
        let signer = HybridSigner::generate(&mut OsRng).unwrap();
        let pk = signer.public_key();
        let sig = signer.sign(b"hello world").unwrap();
        HybridSigner::verify(b"hello world", &sig, &pk).expect("hybrid verify should pass");
    }

    #[test]
    fn classical_only_fails() {
        let signer = HybridSigner::generate(&mut OsRng).unwrap();
        let pk = signer.public_key();
        let mut sig = signer.sign(b"hello world").unwrap();
        sig.classical[0] ^= 0xFF; // corrupt Ed25519 half only
        let err = HybridSigner::verify(b"hello world", &sig, &pk).unwrap_err();
        assert_eq!(err, SigError::HybridClassicalFailed);
    }

    #[test]
    fn pqc_only_fails() {
        let signer = HybridSigner::generate(&mut OsRng).unwrap();
        let pk = signer.public_key();
        let mut sig = signer.sign(b"hello world").unwrap();
        sig.pqc[0] ^= 0xFF; // corrupt ML-DSA-65 half only
        let err = HybridSigner::verify(b"hello world", &sig, &pk).unwrap_err();
        assert_eq!(err, SigError::HybridPqcFailed);
    }

    #[test]
    fn both_fail() {
        let signer = HybridSigner::generate(&mut OsRng).unwrap();
        let pk = signer.public_key();
        let mut sig = signer.sign(b"hello world").unwrap();
        sig.classical[0] ^= 0xFF;
        sig.pqc[0] ^= 0xFF;
        // Classical is checked first; either failure code is an acceptable fail-closed result.
        let err = HybridSigner::verify(b"hello world", &sig, &pk).unwrap_err();
        assert!(err == SigError::HybridClassicalFailed || err == SigError::HybridPqcFailed);
    }

    #[test]
    fn wrong_message_fails() {
        let signer = HybridSigner::generate(&mut OsRng).unwrap();
        let pk = signer.public_key();
        let sig = signer.sign(b"correct message").unwrap();
        assert!(HybridSigner::verify(b"wrong message", &sig, &pk).is_err());
    }

    #[test]
    fn json_round_trip() {
        let signer = HybridSigner::generate(&mut OsRng).unwrap();
        let pk = signer.public_key();
        let sig = signer.sign(b"hello world").unwrap();

        let pk2 = HybridPublicKey::from_json(&pk.to_json().unwrap()).unwrap();
        let sig2 = HybridSignature::from_json(&sig.to_json().unwrap()).unwrap();
        assert_eq!(pk, pk2);
        assert_eq!(sig, sig2);
        HybridSigner::verify(b"hello world", &sig2, &pk2).expect("round-tripped hybrid verify should pass");
    }

    // ── from_ed25519_secret / from_secret_key_bytes / secret_key (S-2) ──────────────

    #[test]
    fn from_ed25519_secret_preserves_classical_key() {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let legacy_vk = Ed25519SigningKey::from_bytes(&seed).verifying_key();

        let signer = HybridSigner::from_ed25519_secret(&mut OsRng, &seed).unwrap();
        let pk = signer.public_key();

        assert_eq!(pk.classical, legacy_vk.to_bytes().to_vec());
    }

    #[test]
    fn from_ed25519_secret_signs_and_verifies() {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let signer = HybridSigner::from_ed25519_secret(&mut OsRng, &seed).unwrap();
        let pk = signer.public_key();
        let sig = signer.sign(b"bridged agent message").unwrap();
        HybridSigner::verify(b"bridged agent message", &sig, &pk)
            .expect("signature from a bridged Ed25519 key must verify");
    }

    #[test]
    fn secret_key_round_trip_reproduces_public_key_and_signatures() {
        let signer = HybridSigner::generate(&mut OsRng).unwrap();
        let pk = signer.public_key();
        let sk = signer.secret_key();

        let restored = HybridSigner::from_secret_key_bytes(&sk.ed25519_seed, &sk.ml_dsa_65).unwrap();
        let restored_pk = restored.public_key();
        assert_eq!(pk, restored_pk, "restored signer must have an identical public key");

        // The original signer's signature must verify under the restored public key,
        // and vice versa.
        let sig = signer.sign(b"persisted identity").unwrap();
        HybridSigner::verify(b"persisted identity", &sig, &restored_pk)
            .expect("original signature must verify under the restored public key");

        let sig2 = restored.sign(b"persisted identity").unwrap();
        HybridSigner::verify(b"persisted identity", &sig2, &pk)
            .expect("restored signature must verify under the original public key");
    }

    #[test]
    fn secret_key_debug_is_redacted() {
        let signer = HybridSigner::generate(&mut OsRng).unwrap();
        let sk = signer.secret_key();
        let debug = format!("{:?}", sk);
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains(&hex_encode(&sk.ed25519_seed)));
    }

    fn hex_encode(bytes: &[u8]) -> alloc::string::String {
        use core::fmt::Write;
        let mut s = alloc::string::String::with_capacity(bytes.len() * 2);
        for b in bytes {
            let _ = write!(s, "{:02x}", b);
        }
        s
    }

    // ── sign_ctx / verify_ctx (S-1 parity) ──────────────────────────────────────────

    #[test]
    fn sign_ctx_round_trip() {
        let signer = HybridSigner::generate(&mut OsRng).unwrap();
        let pk = signer.public_key();
        let sig = signer.sign_ctx(&mut OsRng, b"8gentz-agent-v1", b"hello").unwrap();
        HybridSigner::verify_ctx(&pk, b"8gentz-agent-v1", b"hello", &sig)
            .expect("sign_ctx/verify_ctx round-trip should pass");
    }

    #[test]
    fn sign_ctx_wrong_ctx_fails() {
        let signer = HybridSigner::generate(&mut OsRng).unwrap();
        let pk = signer.public_key();
        let sig = signer.sign_ctx(&mut OsRng, b"8gentz-agent-v1", b"hello").unwrap();
        let err = HybridSigner::verify_ctx(&pk, b"8gentz-fabric-v1", b"hello", &sig).unwrap_err();
        assert!(err == SigError::HybridClassicalFailed || err == SigError::HybridPqcFailed);
    }

    #[test]
    fn sign_ctx_mode_separation_from_plain_sign() {
        let signer = HybridSigner::generate(&mut OsRng).unwrap();
        let pk = signer.public_key();

        // A plain sign() signature must NOT verify via verify_ctx(&[]).
        let plain_sig = signer.sign(b"hello").unwrap();
        assert!(
            HybridSigner::verify_ctx(&pk, &[], b"hello", &plain_sig).is_err(),
            "plain sign() signature must not verify via verify_ctx(pk, &[], m, sig)"
        );

        // A sign_ctx(&[]) signature must NOT verify via plain verify().
        let ctx_sig = signer.sign_ctx(&mut OsRng, &[], b"hello").unwrap();
        assert!(
            HybridSigner::verify(b"hello", &ctx_sig, &pk).is_err(),
            "sign_ctx(&[]) signature must not verify via plain verify()"
        );
    }

    #[test]
    fn sign_ctx_too_long_context_rejected() {
        let signer = HybridSigner::generate(&mut OsRng).unwrap();
        let pk = signer.public_key();
        let long_ctx = vec![0u8; 256];

        let err = signer.sign_ctx(&mut OsRng, &long_ctx, b"hello").unwrap_err();
        assert_eq!(err, SigError::ContextTooLong { len: 256 });

        let sig = signer.sign_ctx(&mut OsRng, b"ok-ctx", b"hello").unwrap();
        let err = HybridSigner::verify_ctx(&pk, &long_ctx, b"hello", &sig).unwrap_err();
        assert_eq!(err, SigError::ContextTooLong { len: 256 });
    }

    #[test]
    fn sign_ctx_classical_tamper_fails_classical() {
        let signer = HybridSigner::generate(&mut OsRng).unwrap();
        let pk = signer.public_key();
        let mut sig = signer.sign_ctx(&mut OsRng, b"8gentz-agent-v1", b"hello").unwrap();
        sig.classical[0] ^= 0xFF;
        let err = HybridSigner::verify_ctx(&pk, b"8gentz-agent-v1", b"hello", &sig).unwrap_err();
        assert_eq!(err, SigError::HybridClassicalFailed);
    }

    #[test]
    fn sign_ctx_pqc_tamper_fails_pqc() {
        let signer = HybridSigner::generate(&mut OsRng).unwrap();
        let pk = signer.public_key();
        let mut sig = signer.sign_ctx(&mut OsRng, b"8gentz-agent-v1", b"hello").unwrap();
        sig.pqc[0] ^= 0xFF;
        let err = HybridSigner::verify_ctx(&pk, b"8gentz-agent-v1", b"hello", &sig).unwrap_err();
        assert_eq!(err, SigError::HybridPqcFailed);
    }
}
