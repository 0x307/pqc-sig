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

extern crate alloc;
use alloc::{format, vec::Vec};

use ed25519_dalek::{
    Signature as Ed25519Signature, Signer, SigningKey as Ed25519SigningKey,
    Verifier, VerifyingKey as Ed25519VerifyingKey,
};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::error::{SigError, SigResult};
use crate::fips204::MlDsa65Keypair;
use crate::types::{
    deserialize_bytes_base64url, serialize_bytes_base64url, SigAlgorithm, SigPublicKey, Signature,
};

/// Algorithm identifier for this hybrid combination.
pub const HYBRID_ALGORITHM: &str = "ed25519+ml_dsa_65";

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
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
