//! # pqc-sig — Post-Quantum Digital Signatures
//!
//! A standalone, WASM-compatible library implementing post-quantum signature algorithms:
//!
//! - **ML-DSA** (NIST FIPS 204) — Primary standard, pure Rust, WASM-native. `ml-dsa` feature (default)
//!   - [`fips204::MlDsa44Keypair`] — Security Level 2
//!   - [`fips204::MlDsa65Keypair`] — Security Level 3 (recommended)
//!   - [`fips204::MlDsa87Keypair`] — Security Level 5
//!
//! - **SLH-DSA** (NIST FIPS 205) — Stateless hash-based, pure Rust, WASM-native. `slh-dsa` feature (default)
//!   - SHA2 variants: 128s/128f, 192s/192f, 256s/256f
//!   - SHAKE variants: 128s/128f, 192s/192f, 256s/256f
//!
//! - **FN-DSA** (NIST FIPS 206 / Falcon) — requires `fndsa` feature, pure Rust, WASM-compatible
//!   - [`fips206::FnDsa512Keypair`] — Security Level 1
//!   - [`fips206::FnDsa1024Keypair`] — Security Level 5
//!   - Multikey/DID Document encoding works via a provisional `0x307`-reserved private-use
//!     multicodec code (no upstream multiformats/multicodec registration exists yet) — see
//!     [`types::FN_DSA_PRIVATE_USE_BASE`].
//!
//! - **Hybrid Ed25519 + ML-DSA-65** — requires `hybrid` feature; classical/PQC combiner for migration bridging
//!   - [`hybrid::HybridSigner`]
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
//! ## Domain separation
//!
//! Every algorithm family (ML-DSA, SLH-DSA, and — behind the `fndsa` feature — FN-DSA)
//! also exposes a `sign_ctx`/`sign_ctx_deterministic`/`verify_ctx` trio that takes a FIPS
//! 204/205/206 "context" byte string (≤ [`MAX_CONTEXT_LEN`] bytes) in addition to the
//! message. Use this to bind a signature to a specific application or protocol so that a
//! signature produced for one purpose cannot be replayed as valid for another:
//!
//! ```rust,no_run
//! use pqc_sig::fips204::MlDsa65Keypair;
//! use rand::rngs::OsRng;
//!
//! let keypair = MlDsa65Keypair::generate(&mut OsRng).unwrap();
//! let pk = keypair.public_key();
//! let msg = b"Hello, post-quantum world!";
//!
//! let sig = keypair.sign_ctx(&mut OsRng, b"8gentz-agent-v1", msg).unwrap();
//! MlDsa65Keypair::verify_ctx(&pk, b"8gentz-agent-v1", msg, &sig).unwrap();
//!
//! // A signature made under one context MUST NOT verify under another.
//! assert!(MlDsa65Keypair::verify_ctx(&pk, b"8gentz-fabric-v1", msg, &sig).is_err());
//! ```
//!
//! An empty context (`&[]`) is byte-identical to the plain, non-`ctx` API: `sign_ctx(&[],
//! m)`/`sign_ctx_deterministic(&[], m)` produce the same signature as `sign`/
//! `sign_deterministic`, and `verify_ctx(pk, &[], m, sig)` accepts anything `verify` does
//! (and vice versa). See [`MAX_CONTEXT_LEN`] for the 255-byte limit shared by all three
//! FIPS standards, and `examples/domain_separation.rs` for a runnable walkthrough.
//!
//! ## Pre-hash signing (large payloads)
//!
//! Every algorithm family also exposes a `sign_prehash`/`sign_prehash_deterministic`/
//! `verify_prehash` trio for signing very large payloads (multi-MB WASM modules, log
//! bundles, ...) without holding the whole message in memory twice. The **caller**
//! hashes the payload once with an approved [`prehash::PreHash`] function — this crate
//! never hashes on the caller's behalf — and passes the resulting digest:
//!
//! ```rust,no_run
//! use pqc_sig::fips204::MlDsa65Keypair;
//! use pqc_sig::prehash::PreHash;
//! use rand::rngs::OsRng;
//!
//! let keypair = MlDsa65Keypair::generate(&mut OsRng).unwrap();
//! let pk = keypair.public_key();
//!
//! // The host already hashes large payloads ad hoc; feed that digest in directly.
//! let digest = [0x11u8; 64]; // stand-in for e.g. Sha512::digest(&module_bytes)
//!
//! let sig = keypair
//!     .sign_prehash_deterministic(b"8gentz-module-v1", PreHash::Sha512, &digest)
//!     .unwrap();
//! MlDsa65Keypair::verify_prehash(&pk, b"8gentz-module-v1", PreHash::Sha512, &digest, &sig)
//!     .unwrap();
//! ```
//!
//! For **ML-DSA** and **SLH-DSA**, this is the literal FIPS `HashML-DSA`/`HashSLH-DSA`
//! construction (FIPS 204 §5.4 Algorithm 4/5, FIPS 205 §10.2.2 Algorithm 23/25): it
//! builds `M' = 0x01 ‖ len(ctx) ‖ ctx ‖ OID(hash) ‖ digest` and signs/verifies `M'` via
//! the upstream `ml-dsa`/`slh-dsa` crates' `sign_internal`/`verify_internal` and
//! `slh_sign_internal`/`slh_verify_internal` primitives — both confirmed `pub` and
//! reachable in the pinned versions. This is byte-for-byte interoperable with any other
//! conformant `HashML-DSA`/`HashSLH-DSA` implementation. **FN-DSA**'s `sign_prehash`/
//! `verify_prehash` use the upstream `fn-dsa` crate's native `HashIdentifier`
//! pre-hash support directly (FIPS 206 draft framing, performed by `fn-dsa` itself).
//!
//! The pre-hash function's collision strength must be at least the parameter set's
//! security strength (each keypair type exposes this as `SECURITY_STRENGTH_BITS`):
//! 128 bits for ML-DSA-44/SLH-DSA-128\*/FN-DSA-512, 192 bits for ML-DSA-65/
//! SLH-DSA-192\*, 256 bits for ML-DSA-87/SLH-DSA-256\*/FN-DSA-1024. Violating this
//! returns [`SigError::PreHashTooWeak`]; a digest of the wrong length for the chosen
//! [`prehash::PreHash`] returns [`SigError::InvalidDigestLength`]. A pre-hash signature
//! does **not** verify via `verify`/`verify_ctx` (and vice versa) — the leading `0x01`
//! domain byte structurally separates the two modes. See `examples/prehash_large_payload.rs`
//! for a runnable walkthrough with a multi-MB payload.
//!
//! ## Hybrid bridge (migrating a classical identity)
//!
//! The `hybrid` feature's [`hybrid::HybridSigner`] also supports bridging an *existing*
//! classical Ed25519 identity — rather than only generating a brand-new one — via
//! [`hybrid::HybridSigner::from_ed25519_secret`], plus a `secret_key()`/
//! `from_secret_key_bytes` pair for persisting both halves across restarts, and its own
//! domain-separated `sign_ctx`/`verify_ctx` trio (S-1 parity, with a crate-defined
//! Ed25519 context framing since RFC 8032 has none — see
//! [`hybrid::HYBRID_CTX_FRAME_DOMAIN`]). See `examples/hybrid_bridge.rs` for a runnable
//! walkthrough and `docs/SAGP_NOTES.md` for Wave-1 migration guidance.
//!
//! ## WASM Usage
//!
//! This crate is a pure library (rlib-only) and is never built as a standalone WASM
//! artifact itself. For WASM/JS bindings, use the sibling `pqc-sig-wasm` crate.
//!
//! ## Encoding only
//!
//! With `default-features = false` and no algorithm feature, the crate is the encoding
//! surface alone: [`SigAlgorithm`], [`SigPublicKey`], [`Signature`], [`SignedMessage`],
//! multicodec codes, W3C Multikey, base64url and JSON. No signature implementation is
//! compiled in, and CI checks the dependency graph to keep it that way. Use this when you
//! only carry keys and signatures between systems, for example in a DID tool or an SDK
//! whose signing happens elsewhere. The encodings are byte-identical to the full build's.
//! ```toml
//! pqc-sig = { version = "0.5", default-features = false, features = ["std"] }
//! ```
//!
//! ## `no_std` Support
//!
//! This crate is `no_std`-compatible with `alloc`. Disable the `std` feature and keep the
//! algorithms you use:
//! ```toml
//! pqc-sig = { version = "0.5", default-features = false, features = ["ml-dsa", "slh-dsa"] }
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

/// Domain-separation context helpers shared by `sign_ctx`/`verify_ctx` across all
/// algorithm families. See the crate-level "Domain separation" docs above.
// Its check is only called by the algorithm modules; the encoding-only build keeps the
// public `MAX_CONTEXT_LEN` constant.
#[cfg_attr(not(any(feature = "ml-dsa", feature = "slh-dsa", feature = "fndsa")), allow(dead_code))]
mod ctx;

/// Pre-hash signing support (`HashML-DSA`/`HashSLH-DSA`/FN-DSA pre-hashed mode) shared
/// by `sign_prehash`/`sign_prehash_deterministic`/`verify_prehash` across all algorithm
/// families. See the crate-level "Pre-hash signing" docs above.
pub mod prehash;

/// ML-DSA (NIST FIPS 204) — pure Rust, WASM-native. Requires the `ml-dsa` feature (default).
#[cfg(feature = "ml-dsa")]
pub mod fips204;

/// SLH-DSA (NIST FIPS 205) — pure Rust, WASM-native. Requires the `slh-dsa` feature (default).
#[cfg(feature = "slh-dsa")]
pub mod fips205;

/// FN-DSA / Falcon (NIST FIPS 206) — requires `fndsa` feature, pure Rust, WASM-compatible.
#[cfg(feature = "fndsa")]
pub mod fips206;

/// Hybrid classical + post-quantum signatures (Ed25519 + ML-DSA-65) — requires `hybrid` feature.
#[cfg(feature = "hybrid")]
pub mod hybrid;

// ── Top-Level Re-exports ──────────────────────────────────────────────────────

pub use error::{SigError, SigResult};
pub use types::{SigAlgorithm, SigPublicKey, SigSecretKey, Signature, SignedMessage};
pub use ctx::MAX_CONTEXT_LEN;
pub use prehash::PreHash;

// FIPS 204 — ML-DSA (feature-gated, default)
#[cfg(feature = "ml-dsa")]
pub use fips204::{MlDsa44Keypair, MlDsa65Keypair, MlDsa87Keypair};

// FIPS 205 — SLH-DSA (feature-gated, default)
#[cfg(feature = "slh-dsa")]
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

// Hybrid Ed25519 + ML-DSA-65 (feature-gated)
#[cfg(feature = "hybrid")]
pub use hybrid::{HybridPublicKey, HybridSignature, HybridSigner};

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
