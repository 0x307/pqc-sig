//! Pre-hash signing support for HashML-DSA (FIPS 204 §5.4) / HashSLH-DSA (FIPS 205
//! §10.2.2), plus the equivalent native pre-hashed mode of FN-DSA (FIPS 206 draft).
//!
//! This module never hashes anything itself — the caller hashes the (possibly large)
//! message once with an approved hash function and passes the resulting `digest` to
//! `sign_prehash`/`verify_prehash`. That lets very large payloads (multi-MB WASM
//! modules, log bundles, etc.) be signed without holding the whole message in memory
//! twice or re-absorbing it into the signature scheme's own hash.
//!
//! # Construction (spec-conformant path)
//!
//! For **ML-DSA** and **SLH-DSA**, this crate implements the literal FIPS
//! `HashML-DSA`/`HashSLH-DSA` construction, not a "just sign the digest bytes"
//! shortcut: it builds
//!
//! ```text
//! M' = 0x01 ‖ u8(len(ctx)) ‖ ctx ‖ OID(hash) ‖ digest
//! ```
//!
//! (FIPS 204 §5.4.1 Algorithm 4 / FIPS 205 §10.2.2 Algorithm 23) and signs/verifies `M'`
//! via the upstream `ml-dsa`/`slh-dsa` crates' internal primitives
//! (`ExpandedSigningKey::sign_internal`/`VerifyingKey::verify_internal` for ML-DSA;
//! `SigningKey::slh_sign_internal`/`VerifyingKey::slh_verify_internal` for SLH-DSA —
//! both `pub`, confirmed reachable in `ml-dsa 0.1.1`/`slh-dsa 0.2.0-rc.5`). This is
//! byte-for-byte the same construction FIPS 204/205 define, so it interoperates with
//! any other conformant HashML-DSA/HashSLH-DSA implementation (OpenSSL 3.5+, liboqs,
//! ...). The leading `0x01` domain byte structurally separates pre-hash signatures from
//! pure-mode signatures (which use `0x00`): a `sign_prehash` signature does **not**
//! verify via `verify`/`verify_ctx`, and vice versa.
//!
//! **FN-DSA** has native pre-hash support (`fn-dsa`'s `HashIdentifier`/`DomainContext`
//! parameters), so its `sign_prehash`/`verify_prehash` pass `digest` straight through to
//! the upstream crate, which performs the FIPS 206 (draft) framing itself.
//!
//! # Collision-strength enforcement
//!
//! FIPS 204 §5.4 / FIPS 205 §10.2.2 require the pre-hash function's collision strength
//! to be at least the signature parameter set's security strength. This module encodes
//! that as [`PreHash::collision_strength_bits`], and every `sign_prehash`/
//! `sign_prehash_deterministic`/`verify_prehash` method checks it against the
//! keypair's `SECURITY_STRENGTH_BITS` constant before calling into upstream code,
//! returning [`crate::SigError::PreHashTooWeak`] on failure (e.g. `PreHash::Sha256` is
//! rejected for `MlDsa65Keypair`/`MlDsa87Keypair`).

extern crate alloc;
use alloc::vec::Vec;

use crate::error::{SigError, SigResult};

/// Approved pre-hash functions for `HashML-DSA`/`HashSLH-DSA`/FN-DSA pre-hashed mode.
///
/// The caller is responsible for computing the digest; this crate does not hash on
/// the caller's behalf (no hashing dependency is added to `[dependencies]` — see the
/// module docs above). `oid_der()`/`digest_len()`/`collision_strength_bits()` follow
/// FIPS 204 §5.4.1's OID table and RFC 8017 / NIST CSOR DER encodings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PreHash {
    /// SHA-256 (128-bit collision strength, 32-byte digest).
    Sha256,
    /// SHA-384 (192-bit collision strength, 48-byte digest).
    Sha384,
    /// SHA-512 (256-bit collision strength, 64-byte digest).
    Sha512,
    /// SHA3-256 (128-bit collision strength, 32-byte digest).
    Sha3_256,
    /// SHA3-384 (192-bit collision strength, 48-byte digest).
    Sha3_384,
    /// SHA3-512 (256-bit collision strength, 64-byte digest).
    Sha3_512,
    /// SHAKE128 with a 256-bit (32-byte) output (128-bit collision strength).
    Shake128,
    /// SHAKE256 with a 512-bit (64-byte) output (256-bit collision strength).
    Shake256,
}

impl PreHash {
    /// The full DER TLV encoding of this hash function's OID (FIPS 204 §5.4.1 / RFC
    /// 8017 / NIST CSOR), e.g. SHA-256 = `06 09 60 86 48 01 65 03 04 02 01`.
    pub const fn oid_der(self) -> &'static [u8] {
        match self {
            PreHash::Sha256 => &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01],
            PreHash::Sha384 => &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02],
            PreHash::Sha512 => &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03],
            PreHash::Sha3_256 => &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08],
            PreHash::Sha3_384 => &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09],
            PreHash::Sha3_512 => &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0A],
            PreHash::Shake128 => &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0B],
            PreHash::Shake256 => &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0C],
        }
    }

    /// The expected digest length in bytes. SHAKE128's output is fixed at 256 bits (32
    /// bytes) and SHAKE256's at 512 bits (64 bytes) for this purpose (FIPS 204 §5.4.1).
    pub const fn digest_len(self) -> usize {
        match self {
            PreHash::Sha256 => 32,
            PreHash::Sha384 => 48,
            PreHash::Sha512 => 64,
            PreHash::Sha3_256 => 32,
            PreHash::Sha3_384 => 48,
            PreHash::Sha3_512 => 64,
            PreHash::Shake128 => 32,
            PreHash::Shake256 => 64,
        }
    }

    /// Collision strength in bits, used to enforce FIPS 204 §5.4 / FIPS 205 §10.2.2's
    /// "pre-hash strength must be >= the parameter set's security strength" rule.
    pub const fn collision_strength_bits(self) -> u32 {
        match self {
            PreHash::Sha256 => 128,
            PreHash::Sha384 => 192,
            PreHash::Sha512 => 256,
            PreHash::Sha3_256 => 128,
            PreHash::Sha3_384 => 192,
            PreHash::Sha3_512 => 256,
            PreHash::Shake128 => 128,
            PreHash::Shake256 => 256,
        }
    }

    /// A human-readable name for this hash function, used in error messages.
    pub const fn name(self) -> &'static str {
        match self {
            PreHash::Sha256 => "SHA-256",
            PreHash::Sha384 => "SHA-384",
            PreHash::Sha512 => "SHA-512",
            PreHash::Sha3_256 => "SHA3-256",
            PreHash::Sha3_384 => "SHA3-384",
            PreHash::Sha3_512 => "SHA3-512",
            PreHash::Shake128 => "SHAKE128",
            PreHash::Shake256 => "SHAKE256",
        }
    }
}

/// Build `M' = 0x01 ‖ u8(len(ctx)) ‖ ctx ‖ OID(hash) ‖ digest` (FIPS 204 §5.4.1 /
/// FIPS 205 §10.2.2). Callers must validate `ctx.len() <= `[`crate::MAX_CONTEXT_LEN`]
/// (via the crate-private `check_ctx` helper) *before* calling this — it assumes that
/// invariant already holds and truncates silently otherwise.
// Called only by ML-DSA and SLH-DSA (FN-DSA frames its pre-hash differently); unused
// without them.
#[cfg_attr(not(any(feature = "ml-dsa", feature = "slh-dsa")), allow(dead_code))]
pub(crate) fn frame_prehash(ctx: &[u8], hash: PreHash, digest: &[u8]) -> Vec<u8> {
    let oid = hash.oid_der();
    let mut out = Vec::with_capacity(2 + ctx.len() + oid.len() + digest.len());
    out.push(0x01);
    out.push(ctx.len() as u8);
    out.extend_from_slice(ctx);
    out.extend_from_slice(oid);
    out.extend_from_slice(digest);
    out
}

/// Validate a pre-hash digest against its expected length and against the calling
/// algorithm's required collision strength.
///
/// Returns [`SigError::InvalidDigestLength`] if `digest.len() != hash.digest_len()`,
/// or [`SigError::PreHashTooWeak`] if `hash.collision_strength_bits() < required_bits`.
/// `algorithm` should be the human-readable algorithm name (e.g. `"ML-DSA-65"`) used in
/// the error message.
// Called only by the algorithm modules; unused in the encoding-only build.
#[cfg_attr(not(any(feature = "ml-dsa", feature = "slh-dsa", feature = "fndsa")), allow(dead_code))]
pub(crate) fn check_prehash(
    hash: PreHash,
    digest: &[u8],
    required_bits: u32,
    algorithm: &'static str,
) -> SigResult<()> {
    let expected = hash.digest_len();
    if digest.len() != expected {
        return Err(SigError::InvalidDigestLength {
            hash: hash.name(),
            expected,
            got: digest.len(),
        });
    }
    let strength = hash.collision_strength_bits();
    if strength < required_bits {
        return Err(SigError::PreHashTooWeak {
            hash: hash.name(),
            strength,
            algorithm,
            required: required_bits,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oid_der_matches_fips_204_table() {
        assert_eq!(
            PreHash::Sha256.oid_der(),
            &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]
        );
        assert_eq!(
            PreHash::Sha384.oid_der(),
            &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02]
        );
        assert_eq!(
            PreHash::Sha512.oid_der(),
            &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03]
        );
        assert_eq!(
            PreHash::Sha3_256.oid_der(),
            &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08]
        );
        assert_eq!(
            PreHash::Sha3_384.oid_der(),
            &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09]
        );
        assert_eq!(
            PreHash::Sha3_512.oid_der(),
            &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0A]
        );
        assert_eq!(
            PreHash::Shake128.oid_der(),
            &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0B]
        );
        assert_eq!(
            PreHash::Shake256.oid_der(),
            &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0C]
        );
        // Every OID is an 11-byte DER TLV: 0x06 0x09 (SEQUENCE tag omitted; this is the
        // OID itself: tag 0x06, length 0x09, 9-byte body).
        for h in [
            PreHash::Sha256, PreHash::Sha384, PreHash::Sha512,
            PreHash::Sha3_256, PreHash::Sha3_384, PreHash::Sha3_512,
            PreHash::Shake128, PreHash::Shake256,
        ] {
            assert_eq!(h.oid_der().len(), 11);
            assert_eq!(h.oid_der()[0], 0x06);
            assert_eq!(h.oid_der()[1], 0x09);
        }
    }

    #[test]
    fn digest_len_matches_hash_output_size() {
        assert_eq!(PreHash::Sha256.digest_len(), 32);
        assert_eq!(PreHash::Sha384.digest_len(), 48);
        assert_eq!(PreHash::Sha512.digest_len(), 64);
        assert_eq!(PreHash::Sha3_256.digest_len(), 32);
        assert_eq!(PreHash::Sha3_384.digest_len(), 48);
        assert_eq!(PreHash::Sha3_512.digest_len(), 64);
        assert_eq!(PreHash::Shake128.digest_len(), 32);
        assert_eq!(PreHash::Shake256.digest_len(), 64);
    }

    #[test]
    fn collision_strength_bits_matches_fips_table() {
        assert_eq!(PreHash::Sha256.collision_strength_bits(), 128);
        assert_eq!(PreHash::Sha384.collision_strength_bits(), 192);
        assert_eq!(PreHash::Sha512.collision_strength_bits(), 256);
        assert_eq!(PreHash::Sha3_256.collision_strength_bits(), 128);
        assert_eq!(PreHash::Sha3_384.collision_strength_bits(), 192);
        assert_eq!(PreHash::Sha3_512.collision_strength_bits(), 256);
        assert_eq!(PreHash::Shake128.collision_strength_bits(), 128);
        assert_eq!(PreHash::Shake256.collision_strength_bits(), 256);
    }

    #[test]
    fn name_is_human_readable() {
        assert_eq!(PreHash::Sha256.name(), "SHA-256");
        assert_eq!(PreHash::Shake256.name(), "SHAKE256");
    }

    #[test]
    fn frame_prehash_layout() {
        let ctx = b"8gentz-agent-v1";
        let digest = [0x42u8; 32];
        let m_prime = frame_prehash(ctx, PreHash::Sha256, &digest);

        assert_eq!(m_prime[0], 0x01, "domain byte must be 0x01 for pre-hash mode");
        assert_eq!(m_prime[1], ctx.len() as u8, "second byte must be len(ctx)");
        assert_eq!(&m_prime[2..2 + ctx.len()], ctx, "ctx must follow the length byte");
        let oid = PreHash::Sha256.oid_der();
        assert_eq!(
            &m_prime[2 + ctx.len()..2 + ctx.len() + oid.len()],
            oid,
            "OID must follow ctx"
        );
        assert_eq!(
            &m_prime[2 + ctx.len() + oid.len()..],
            &digest[..],
            "digest must follow the OID"
        );
        assert_eq!(m_prime.len(), 2 + ctx.len() + oid.len() + digest.len());
    }

    #[test]
    fn frame_prehash_empty_ctx() {
        let digest = [0u8; 64];
        let m_prime = frame_prehash(&[], PreHash::Sha512, &digest);
        assert_eq!(m_prime[0], 0x01);
        assert_eq!(m_prime[1], 0);
        assert_eq!(&m_prime[2..13], PreHash::Sha512.oid_der());
        assert_eq!(&m_prime[13..], &digest[..]);
    }

    #[test]
    fn check_prehash_rejects_wrong_digest_length() {
        let digest = [0u8; 31]; // SHA-256 wants 32
        match check_prehash(PreHash::Sha256, &digest, 128, "ML-DSA-44") {
            Err(SigError::InvalidDigestLength { hash, expected, got }) => {
                assert_eq!(hash, "SHA-256");
                assert_eq!(expected, 32);
                assert_eq!(got, 31);
            }
            other => panic!("expected InvalidDigestLength, got {other:?}"),
        }
    }

    #[test]
    fn check_prehash_rejects_weak_hash() {
        let digest = [0u8; 32];
        match check_prehash(PreHash::Sha256, &digest, 192, "ML-DSA-65") {
            Err(SigError::PreHashTooWeak { hash, strength, algorithm, required }) => {
                assert_eq!(hash, "SHA-256");
                assert_eq!(strength, 128);
                assert_eq!(algorithm, "ML-DSA-65");
                assert_eq!(required, 192);
            }
            other => panic!("expected PreHashTooWeak, got {other:?}"),
        }
    }

    #[test]
    fn check_prehash_accepts_sufficient_strength() {
        let digest = [0u8; 64];
        assert!(check_prehash(PreHash::Sha512, &digest, 256, "ML-DSA-87").is_ok());
    }
}
