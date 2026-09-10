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

    /// Domain-separation context string exceeds the FIPS 204/205/206 255-byte maximum.
    ///
    /// FIPS 204 §5.2, FIPS 205 §10.2, and the FIPS 206 (draft) `DomainContext` construction
    /// all encode the context length in a single byte, capping it at 255 bytes. Returned by
    /// every `sign_ctx`/`sign_ctx_deterministic`/`verify_ctx` method before it would
    /// otherwise hit an opaque error from the underlying `ml-dsa`/`slh-dsa`/`fn-dsa` crate.
    #[error("context string too long: {len} bytes (max 255)")]
    ContextTooLong { len: usize },

    /// Pre-hash digest length does not match the expected output size of the named
    /// hash function (FIPS 204 §5.4.1 / FIPS 205 §10.2.2).
    ///
    /// Returned by every `sign_prehash`/`sign_prehash_deterministic`/`verify_prehash`
    /// method before it would otherwise sign/verify a malformed digest.
    #[error("digest length for {hash} must be {expected} bytes, got {got}")]
    InvalidDigestLength { hash: &'static str, expected: usize, got: usize },

    /// Pre-hash collision strength is weaker than the signature algorithm's required
    /// security strength (FIPS 204 §5.4 / FIPS 205 §10.2.2).
    ///
    /// For example, `PreHash::Sha256` (128-bit collision strength) is rejected for
    /// `MlDsa65Keypair`/`MlDsa87Keypair` (192/256-bit security strength).
    #[error("pre-hash {hash} ({strength}-bit collision strength) is too weak for {algorithm} (requires >= {required} bits)")]
    PreHashTooWeak { hash: &'static str, strength: u32, algorithm: &'static str, required: u32 },
}

impl SigError {
    /// Convert to a string suitable for crossing the WASM boundary.
    pub fn to_wasm_string(&self) -> String {
        self.to_string()
    }
}

/// Convenience type alias for signature results.
pub type SigResult<T> = Result<T, SigError>;
