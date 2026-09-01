//! Unified error type for the `pqc-sig` crate.
//!
//! All signature operations return `Result<T, SigError>`. This type is designed to be
//! `no_std`-compatible (with `alloc`) and serializable for WASM boundary crossing.

extern crate alloc;
use alloc::string::{String, ToString};

use thiserror::Error;

/// Errors that can occur during signature operations.
#[derive(Debug, Error, Clone, PartialEq)]
pub enum SigError {
    /// Key generation failed (e.g., RNG failure).
    #[error("key generation failed: {0}")]
    KeyGeneration(String),

    /// Signing operation failed.
    #[error("signing failed: {0}")]
    Signing(String),

    /// Signature verification failed (signature is invalid for the given message/key).
    #[error("signature verification failed")]
    VerificationFailed,

    /// Invalid public key (wrong size, wrong algorithm tag, or malformed).
    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),

    /// Invalid secret key (wrong size, wrong algorithm tag, or malformed).
    #[error("invalid secret key: {0}")]
    InvalidSecretKey(String),

    /// Invalid signature (wrong size, wrong algorithm tag, or malformed).
    #[error("invalid signature: {0}")]
    InvalidSignature(String),

    /// Base64 decoding error.
    #[error("base64 decode error: {0}")]
    Base64Decode(String),

    /// JSON serialization/deserialization error.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// The requested algorithm is not available (feature not enabled).
    #[error("algorithm '{name}' not available; enable feature '{feature}'")]
    AlgorithmNotAvailable { name: String, feature: String },

    /// Hybrid signature verification failed on the classical (Ed25519) side.
    #[error("hybrid verification failed: classical (Ed25519) signature invalid")]
    HybridClassicalFailed,

    /// Hybrid signature verification failed on the post-quantum (ML-DSA) side.
    #[error("hybrid verification failed: post-quantum (ML-DSA) signature invalid")]
    HybridPqcFailed,

    /// Generic internal error.
    #[error("internal error: {0}")]
    Internal(String),
}

impl SigError {
    /// Convert to a string suitable for crossing the WASM boundary.
    pub fn to_wasm_string(&self) -> String {
        self.to_string()
    }
}

/// Convenience type alias for signature results.
pub type SigResult<T> = Result<T, SigError>;
