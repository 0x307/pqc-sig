//! # pqc-sig — Post-Quantum Digital Signatures
//!
//! A standalone, WASM-compatible library implementing post-quantum signature algorithms:
//!
//! - **ML-DSA** (NIST FIPS 204) — Primary standard, pure Rust, WASM-native
//!   - [`fips204::MlDsa44Keypair`] — Security Level 2
//!   - [`fips204::MlDsa65Keypair`] — Security Level 3 (recommended)
//!   - [`fips204::MlDsa87Keypair`] — Security Level 5
//!
//! - **SLH-DSA** (NIST FIPS 205) — Stateless hash-based, pure Rust, WASM-native
//!   - SHA2 variants: 128s/128f, 192s/192f, 256s/256f
//!   - SHAKE variants: 128s/128f, 192s/192f, 256s/256f
//!
//! - **FN-DSA** (NIST FIPS 206 / Falcon) — requires `fndsa` feature (C FFI, not WASM)
//!   - [`fips206::FnDsa512Keypair`] — Security Level 1
//!   - [`fips206::FnDsa1024Keypair`] — Security Level 5
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use pqc_sig::fips204::MlDsa65Keypair;
//! use rand::rngs::OsRng;
//!
//! // Generate a keypair
//! let keypair = MlDsa65Keypair::generate(&mut OsRng).unwrap();
//! let pk = keypair.public_key();
//!
//! // Sign a message
//! let message = b"Hello, post-quantum world!";
//! let signature = keypair.sign(&mut OsRng, message).unwrap();
//!
//! // Verify the signature
//! MlDsa65Keypair::verify(&pk, message, &signature).unwrap();
//! ```
//!
//! ## WASM Usage
//!
//! Build with the `wasm` feature for `wasm32-unknown-unknown` targets:
//! ```toml
//! pqc-sig = { version = "0.1", features = ["wasm"] }
//! ```
//!
//! ## `no_std` Support
//!
//! This crate is `no_std`-compatible with `alloc`. Disable the `std` feature:
//! ```toml
//! pqc-sig = { version = "0.1", default-features = false }
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

#[cfg(not(feature = "std"))]
extern crate alloc;

// ── Public Modules ────────────────────────────────────────────────────────────

/// Error types for all signature operations.
pub mod error;

/// Wire types: public keys, secret keys, signatures, algorithm identifiers.
pub mod types;

/// ML-DSA (NIST FIPS 204) — pure Rust, WASM-native.
pub mod fips204;

/// SLH-DSA (NIST FIPS 205) — pure Rust, WASM-native.
pub mod fips205;

/// FN-DSA / Falcon (NIST FIPS 206) — requires `fndsa` feature (C FFI, not WASM).
#[cfg(feature = "fndsa")]
pub mod fips206;

/// WASM bindings via `wasm-bindgen` — requires `wasm` feature.
#[cfg(feature = "wasm")]
pub mod wasm;

// ── Top-Level Re-exports ──────────────────────────────────────────────────────

pub use error::{SigError, SigResult};
pub use types::{SigAlgorithm, SigPublicKey, SigSecretKey, Signature, SignedMessage};

// FIPS 204 — ML-DSA
pub use fips204::{MlDsa44Keypair, MlDsa65Keypair, MlDsa87Keypair};

// FIPS 205 — SLH-DSA
pub use fips205::{
    SlhDsaSha2_128sKeypair, SlhDsaSha2_128fKeypair,
    SlhDsaSha2_192sKeypair, SlhDsaSha2_192fKeypair,
    SlhDsaSha2_256sKeypair, SlhDsaSha2_256fKeypair,
    SlhDsaShake128sKeypair, SlhDsaShake128fKeypair,
    SlhDsaShake192sKeypair, SlhDsaShake192fKeypair,
    SlhDsaShake256sKeypair, SlhDsaShake256fKeypair,
};

// FIPS 206 — FN-DSA (feature-gated)
#[cfg(feature = "fndsa")]
pub use fips206::{FnDsa512Keypair, FnDsa1024Keypair};

// ── Crate Metadata ────────────────────────────────────────────────────────────

/// Crate version string.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Primary signature algorithm (ML-DSA-65, FIPS 204 Level 3).
pub const PRIMARY_ALGORITHM: &str = "ML-DSA-65";

/// Audit signature algorithm (ML-DSA-87, FIPS 204 Level 5).
pub const AUDIT_ALGORITHM: &str = "ML-DSA-87";

/// WASM integrity algorithm (SLH-DSA-SHA2-128s, FIPS 205).
pub const WASM_INTEGRITY_ALGORITHM: &str = "SLH-DSA-SHA2-128s";

/// Compact signature algorithm (FN-DSA-512, FIPS 206).
pub const COMPACT_ALGORITHM: &str = "FN-DSA-512";
