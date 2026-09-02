//! Wire types for PQC signature public keys, secret keys, and signatures.
//!
//! These types are designed for serialization across WASM boundaries and for
//! use in DID Documents (W3C Decentralized Identifiers).
//!
//! All byte arrays are encoded as base64url (no padding) strings in JSON.

extern crate alloc;
use alloc::{format, string::{String, ToString}, vec::Vec};

use base64ct::{Base64Url, Encoding};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{SigError, SigResult};

// ── Algorithm Identifiers ─────────────────────────────────────────────────────

/// Identifies the post-quantum signature algorithm used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SigAlgorithm {
    // FIPS 204 — ML-DSA (Module Lattice Digital Signature Algorithm)
    /// ML-DSA-44 (NIST FIPS 204, Security Level 2)
    MlDsa44,
    /// ML-DSA-65 (NIST FIPS 204, Security Level 3) — recommended default
    MlDsa65,
    /// ML-DSA-87 (NIST FIPS 204, Security Level 5)
    MlDsa87,

    // FIPS 205 — SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)
    /// SLH-DSA-SHA2-128s (NIST FIPS 205, Security Level 1, small signatures)
    SlhDsaSha2_128s,
    /// SLH-DSA-SHA2-128f (NIST FIPS 205, Security Level 1, fast signing)
    SlhDsaSha2_128f,
    /// SLH-DSA-SHA2-192s (NIST FIPS 205, Security Level 3, small signatures)
    SlhDsaSha2_192s,
    /// SLH-DSA-SHA2-192f (NIST FIPS 205, Security Level 3, fast signing)
    SlhDsaSha2_192f,
    /// SLH-DSA-SHA2-256s (NIST FIPS 205, Security Level 5, small signatures)
    SlhDsaSha2_256s,
    /// SLH-DSA-SHA2-256f (NIST FIPS 205, Security Level 5, fast signing)
    SlhDsaSha2_256f,
    /// SLH-DSA-SHAKE-128s (NIST FIPS 205, Security Level 1, small signatures)
    SlhDsaShake128s,
    /// SLH-DSA-SHAKE-128f (NIST FIPS 205, Security Level 1, fast signing)
    SlhDsaShake128f,
    /// SLH-DSA-SHAKE-192s (NIST FIPS 205, Security Level 3, small signatures)
    SlhDsaShake192s,
    /// SLH-DSA-SHAKE-192f (NIST FIPS 205, Security Level 3, fast signing)
    SlhDsaShake192f,
    /// SLH-DSA-SHAKE-256s (NIST FIPS 205, Security Level 5, small signatures)
    SlhDsaShake256s,
    /// SLH-DSA-SHAKE-256f (NIST FIPS 205, Security Level 5, fast signing)
    SlhDsaShake256f,

    // FIPS 206 — FN-DSA (Falcon)
    /// FN-DSA-512 (NIST FIPS 206, Security Level 1) — requires `fndsa` feature
    FnDsa512,
    /// FN-DSA-1024 (NIST FIPS 206, Security Level 5) — requires `fndsa` feature
    FnDsa1024,
}

impl SigAlgorithm {
    /// Returns the canonical string identifier for this algorithm.
    pub fn as_str(&self) -> &'static str {
        match self {
            SigAlgorithm::MlDsa44           => "ML-DSA-44",
            SigAlgorithm::MlDsa65           => "ML-DSA-65",
            SigAlgorithm::MlDsa87           => "ML-DSA-87",
            SigAlgorithm::SlhDsaSha2_128s   => "SLH-DSA-SHA2-128s",
            SigAlgorithm::SlhDsaSha2_128f   => "SLH-DSA-SHA2-128f",
            SigAlgorithm::SlhDsaSha2_192s   => "SLH-DSA-SHA2-192s",
            SigAlgorithm::SlhDsaSha2_192f   => "SLH-DSA-SHA2-192f",
            SigAlgorithm::SlhDsaSha2_256s   => "SLH-DSA-SHA2-256s",
            SigAlgorithm::SlhDsaSha2_256f   => "SLH-DSA-SHA2-256f",
            SigAlgorithm::SlhDsaShake128s   => "SLH-DSA-SHAKE-128s",
            SigAlgorithm::SlhDsaShake128f   => "SLH-DSA-SHAKE-128f",
            SigAlgorithm::SlhDsaShake192s   => "SLH-DSA-SHAKE-192s",
            SigAlgorithm::SlhDsaShake192f   => "SLH-DSA-SHAKE-192f",
            SigAlgorithm::SlhDsaShake256s   => "SLH-DSA-SHAKE-256s",
            SigAlgorithm::SlhDsaShake256f   => "SLH-DSA-SHAKE-256f",
            SigAlgorithm::FnDsa512          => "FN-DSA-512",
            SigAlgorithm::FnDsa1024         => "FN-DSA-1024",
        }
    }

    /// Returns the public key size in bytes for this algorithm.
    pub fn public_key_size(&self) -> usize {
        match self {
            SigAlgorithm::MlDsa44           => 1312,
            SigAlgorithm::MlDsa65           => 1952,
            SigAlgorithm::MlDsa87           => 2592,
            SigAlgorithm::SlhDsaSha2_128s   => 32,
            SigAlgorithm::SlhDsaSha2_128f   => 32,
            SigAlgorithm::SlhDsaSha2_192s   => 48,
            SigAlgorithm::SlhDsaSha2_192f   => 48,
            SigAlgorithm::SlhDsaSha2_256s   => 64,
            SigAlgorithm::SlhDsaSha2_256f   => 64,
            SigAlgorithm::SlhDsaShake128s   => 32,
            SigAlgorithm::SlhDsaShake128f   => 32,
            SigAlgorithm::SlhDsaShake192s   => 48,
            SigAlgorithm::SlhDsaShake192f   => 48,
            SigAlgorithm::SlhDsaShake256s   => 64,
            SigAlgorithm::SlhDsaShake256f   => 64,
            SigAlgorithm::FnDsa512          => 897,
            SigAlgorithm::FnDsa1024         => 1793,
        }
    }

    /// Returns the secret key size in bytes for this algorithm.
    ///
    /// For ML-DSA variants, this returns 32 (the seed size), which is the preferred
    /// serialization per the `ml-dsa` crate. The full expanded key form (2560/4032/4896 bytes)
    /// is deprecated in favor of the compact 32-byte seed.
    pub fn secret_key_size(&self) -> usize {
        match self {
            SigAlgorithm::MlDsa44           => 32,
            SigAlgorithm::MlDsa65           => 32,
            SigAlgorithm::MlDsa87           => 32,
            SigAlgorithm::SlhDsaSha2_128s   => 64,
            SigAlgorithm::SlhDsaSha2_128f   => 64,
            SigAlgorithm::SlhDsaSha2_192s   => 96,
            SigAlgorithm::SlhDsaSha2_192f   => 96,
            SigAlgorithm::SlhDsaSha2_256s   => 128,
            SigAlgorithm::SlhDsaSha2_256f   => 128,
            SigAlgorithm::SlhDsaShake128s   => 64,
            SigAlgorithm::SlhDsaShake128f   => 64,
            SigAlgorithm::SlhDsaShake192s   => 96,
            SigAlgorithm::SlhDsaShake192f   => 96,
            SigAlgorithm::SlhDsaShake256s   => 128,
            SigAlgorithm::SlhDsaShake256f   => 128,
            SigAlgorithm::FnDsa512          => 1281,
            SigAlgorithm::FnDsa1024         => 2305,
        }
    }

    /// Returns the maximum signature size in bytes for this algorithm.
    pub fn signature_size(&self) -> usize {
        match self {
            SigAlgorithm::MlDsa44           => 2420,
            SigAlgorithm::MlDsa65           => 3309,
            SigAlgorithm::MlDsa87           => 4627,
            SigAlgorithm::SlhDsaSha2_128s   => 7856,
            SigAlgorithm::SlhDsaSha2_128f   => 17088,
            SigAlgorithm::SlhDsaSha2_192s   => 16224,
            SigAlgorithm::SlhDsaSha2_192f   => 35664,
            SigAlgorithm::SlhDsaSha2_256s   => 29792,
            SigAlgorithm::SlhDsaSha2_256f   => 49856,
            SigAlgorithm::SlhDsaShake128s   => 7856,
            SigAlgorithm::SlhDsaShake128f   => 17088,
            SigAlgorithm::SlhDsaShake192s   => 16224,
            SigAlgorithm::SlhDsaShake192f   => 35664,
            SigAlgorithm::SlhDsaShake256s   => 29792,
            SigAlgorithm::SlhDsaShake256f   => 49856,
            SigAlgorithm::FnDsa512          => 666,
            SigAlgorithm::FnDsa1024         => 1280,
        }
    }

    /// Returns the FIPS standard number for this algorithm.
    pub fn fips_standard(&self) -> &'static str {
        match self {
            SigAlgorithm::MlDsa44 | SigAlgorithm::MlDsa65 | SigAlgorithm::MlDsa87 => "FIPS-204",
            SigAlgorithm::SlhDsaSha2_128s
            | SigAlgorithm::SlhDsaSha2_128f
            | SigAlgorithm::SlhDsaSha2_192s
            | SigAlgorithm::SlhDsaSha2_192f
            | SigAlgorithm::SlhDsaSha2_256s
            | SigAlgorithm::SlhDsaSha2_256f
            | SigAlgorithm::SlhDsaShake128s
            | SigAlgorithm::SlhDsaShake128f
            | SigAlgorithm::SlhDsaShake192s
            | SigAlgorithm::SlhDsaShake192f
            | SigAlgorithm::SlhDsaShake256s
            | SigAlgorithm::SlhDsaShake256f => "FIPS-205",
            SigAlgorithm::FnDsa512 | SigAlgorithm::FnDsa1024 => "FIPS-206",
        }
    }

    /// Returns the [multicodec](https://github.com/multiformats/multicodec) code for this
    /// algorithm's public key.
    ///
    /// ML-DSA and SLH-DSA codes (`0x1210`–`0x122b`) are registered (draft status) in the
    /// upstream multicodec table. FN-DSA (FIPS 206 / Falcon) has **no upstream-registered**
    /// multicodec code as of this writing — see [`FN_DSA_PRIVATE_USE_BASE`] for the
    /// provisional, 0x307-namespaced private-use codes this crate assigns instead, and its
    /// doc comment for the full rationale, scope, and revisit trigger.
    pub fn multicodec_code(&self) -> SigResult<u32> {
        match self {
            SigAlgorithm::MlDsa44         => Ok(0x1210),
            SigAlgorithm::MlDsa65         => Ok(0x1211),
            SigAlgorithm::MlDsa87         => Ok(0x1212),
            SigAlgorithm::SlhDsaSha2_128s => Ok(0x1220),
            SigAlgorithm::SlhDsaShake128s => Ok(0x1221),
            SigAlgorithm::SlhDsaSha2_128f => Ok(0x1222),
            SigAlgorithm::SlhDsaShake128f => Ok(0x1223),
            SigAlgorithm::SlhDsaSha2_192s => Ok(0x1224),
            SigAlgorithm::SlhDsaShake192s => Ok(0x1225),
            SigAlgorithm::SlhDsaSha2_192f => Ok(0x1226),
            SigAlgorithm::SlhDsaShake192f => Ok(0x1227),
            SigAlgorithm::SlhDsaSha2_256s => Ok(0x1228),
            SigAlgorithm::SlhDsaShake256s => Ok(0x1229),
            SigAlgorithm::SlhDsaSha2_256f => Ok(0x122a),
            SigAlgorithm::SlhDsaShake256f => Ok(0x122b),
            // Provisional, 0x307-reserved private-use codes -- see
            // `FN_DSA_PRIVATE_USE_BASE` doc comment below for full rationale.
            SigAlgorithm::FnDsa512  => Ok(FN_DSA_PRIVATE_USE_BASE),
            SigAlgorithm::FnDsa1024 => Ok(FN_DSA_PRIVATE_USE_BASE + 1),
        }
    }

    /// Returns `true` if this algorithm's [`multicodec_code`](Self::multicodec_code) is one of
    /// this crate's own provisional private-use reservations (currently just FN-DSA), rather
    /// than an upstream-registered multiformats/multicodec table entry.
    ///
    /// Useful for callers who want to warn, log, or otherwise flag when a DID Document /
    /// Multikey they're producing embeds a non-standard code that other multicodec
    /// implementations will not recognize.
    pub fn is_private_use_multicodec(&self) -> bool {
        matches!(self, SigAlgorithm::FnDsa512 | SigAlgorithm::FnDsa1024)
    }
}

/// Base of the **provisional, `0x307`-reserved private-use multicodec range** used for
/// FN-DSA (FIPS 206 / Falcon), because [multiformats/multicodec] has no registered code for
/// FN-DSA/Falcon as of this writing (checked against the live table during the P2/alpha-001
/// implementation pass — no PR, issue, or merged entry exists for FN-DSA/Falcon at either
/// `0x1213` (the next sequential slot after ML-DSA's `0x1210`-`0x1212` block) or elsewhere).
///
/// [multiformats/multicodec]: https://github.com/multiformats/multicodec
///
/// # Decision (per project owner: "reserve and don't block upstream")
///
/// Rather than leaving `to_multibase()`/`from_multibase()` permanently erroring for FN-DSA
/// until an upstream PR lands (outside 0x307's control, no committed timeline), this crate
/// provisionally reserves its own private-use block:
///
/// - **`0x307000`** — `FN-DSA-512` (`SigAlgorithm::FnDsa512`)
/// - **`0x307001`** — `FN-DSA-1024` (`SigAlgorithm::FnDsa1024`)
///
/// `0x307000` is deliberately namespaced after this organization (`0x307`) rather than picked
/// arbitrarily, so a code walking a DID Document that hits an unrecognized `0x307xxx`
/// multicodec prefix has an immediate, greppable clue about its provenance. The
/// `0x307000`-`0x3070ff` block (256 codes) is reserved for this purpose, of which only the
/// first two are in use today — headroom for any future 0x307-authored algorithm that hits
/// the same "real, no upstream multicodec yet" situation FN-DSA is in now.
///
/// # This is intentionally *not* a claim about the officially blessed "Private Use Area"
///
/// The multicodec table's own header comments describe a reserved application-specific /
/// private-use block in the `0x300000`-`0x3fffff` range, and `0x307000` happens to fall
/// inside it — which is a reasonable coincidence given `0x307`'s own numeric name, not proof
/// this crate re-verified that exact boundary byte-for-byte against the live `table.csv`.
/// **Before this crate's FN-DSA Multikey output is ever consumed by a system this
/// organization does not control, re-confirm `0x307000`-`0x3070ff` against the current
/// upstream table** (or complete the real registration PR, which supersedes this reservation
/// entirely — see the revisit trigger below).
///
/// # Consequences and caveats
///
/// - **Interop scope: 0x307-controlled systems only.** Any multibase-encoded FN-DSA public
///   key produced by [`SigPublicKey::to_multibase`] carries this provisional code. A
///   generic/independent multicodec-table-driven decoder (one that doesn't know about
///   `0x307000`/`0x307001` specifically) will not recognize it as FN-DSA — it isn't in the
///   canonical table. This is fine for internal SAGP DID documents (the actual, current use
///   case — see `docs/pqc/migration.md`'s FN-DSA-as-compact-signature design), but it is
///   **not** a substitute for real interop with third-party multicodec/DID tooling.
/// - **Not a breaking change to ship now.** `multicodec_code()` previously returned
///   `Err(..)` for FN-DSA (0.1.0) — turning that into `Ok(..)` is purely additive per
///   `STABILITY.md` §2 ("adding a new public function/return value that previously errored
///   is not breaking unless callers depended on the error"). Nothing in 0.1.0 could have
///   depended on a specific error variant here being permanent, since the doc comment always
///   described this as "not yet supported," not "will never be supported."
/// - **Revisit trigger:** if/when multiformats/multicodec registers an official code for
///   FN-DSA/Falcon, migrate `multicodec_code()` to that value in a follow-up **minor**
///   release (changing an already-provisional, explicitly-flagged-non-final code is not the
///   same kind of break as changing an already-stable one — but it does still change the
///   wire bytes of anything encoded with `0x307000`/`0x307001` in the interim, so it must
///   still carry a `CHANGELOG.md` migration note per `STABILITY.md`, and any 0x307-internal
///   system that persisted FN-DSA Multikeys before that point needs a re-encode pass).
pub const FN_DSA_PRIVATE_USE_BASE: u32 = 0x307000;

/// Encode a multicodec code as an unsigned varint (LEB128, per the
/// [multiformats unsigned-varint spec](https://github.com/multiformats/unsigned-varint)).
fn encode_varint(mut code: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(2);
    loop {
        let mut byte = (code & 0x7f) as u8;
        code >>= 7;
        if code != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if code == 0 {
            break;
        }
    }
    out
}

/// Decode an unsigned varint from the start of `bytes`, returning the decoded value and the
/// number of bytes consumed.
fn decode_varint(bytes: &[u8]) -> SigResult<(u32, usize)> {
    let mut value: u32 = 0;
    for (i, &byte) in bytes.iter().enumerate() {
        if i >= 5 {
            return Err(SigError::InvalidPublicKey("multicodec varint prefix too long".into()));
        }
        value |= ((byte & 0x7f) as u32) << (7 * i);
        if byte & 0x80 == 0 {
            return Ok((value, i + 1));
        }
    }
    Err(SigError::InvalidPublicKey("truncated multicodec varint prefix".into()))
}

impl core::fmt::Display for SigAlgorithm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ── Public Key ────────────────────────────────────────────────────────────────

/// A post-quantum public key with its algorithm tag.
///
/// Public keys are safe to distribute and do not require zeroization.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SigPublicKey {
    /// The algorithm this key belongs to.
    pub algorithm: SigAlgorithm,
    /// Raw public key bytes.
    #[serde(
        serialize_with   = "serialize_bytes_base64url",
        deserialize_with = "deserialize_bytes_base64url"
    )]
    pub bytes: Vec<u8>,
}

impl SigPublicKey {
    /// Create a new public key from raw bytes.
    pub fn new(algorithm: SigAlgorithm, bytes: Vec<u8>) -> Self {
        Self { algorithm, bytes }
    }

    /// Returns the raw bytes of the public key.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Encode the public key bytes as base64url (no padding).
    pub fn to_base64url(&self) -> String {
        Base64Url::encode_string(&self.bytes)
    }

    /// Decode a public key from base64url bytes.
    pub fn from_base64url(algorithm: SigAlgorithm, encoded: &str) -> SigResult<Self> {
        let bytes = Base64Url::decode_vec(encoded)
            .map_err(|e| SigError::Base64Decode(e.to_string()))?;
        Ok(Self { algorithm, bytes })
    }

    /// Encode as a [W3C Multikey](https://www.w3.org/TR/controller-document/#multikey):
    /// a multicodec-prefixed key, multibase-encoded as base58btc with a 'z' prefix.
    ///
    /// Works for all 17 algorithms this crate supports, including FN-DSA — which uses a
    /// provisional, `0x307`-reserved private-use multicodec code rather than an
    /// upstream-registered one; see [`FN_DSA_PRIVATE_USE_BASE`] for the full rationale and
    /// interop scope. In practice this only returns `Err` for malformed/mismatched input, not
    /// for any currently-defined [`SigAlgorithm`] variant.
    pub fn to_multibase(&self) -> SigResult<String> {
        let code = self.algorithm.multicodec_code()?;
        let mut prefixed = encode_varint(code);
        prefixed.extend_from_slice(&self.bytes);

        let mut out = String::with_capacity(prefixed.len() * 2);
        out.push('z');
        out.push_str(&bs58::encode(&prefixed).into_string());
        Ok(out)
    }

    /// Decode from a [W3C Multikey](https://www.w3.org/TR/controller-document/#multikey)
    /// (base58btc with 'z' prefix). Verifies the embedded multicodec code matches `algorithm`.
    pub fn from_multibase(algorithm: SigAlgorithm, multibase: &str) -> SigResult<Self> {
        let expected_code = algorithm.multicodec_code()?;

        let stripped = multibase.strip_prefix('z').ok_or_else(|| {
            SigError::InvalidPublicKey("multibase must start with 'z' (base58btc)".into())
        })?;
        let prefixed = bs58::decode(stripped)
            .into_vec()
            .map_err(|e| SigError::InvalidPublicKey(format!("base58 decode: {}", e)))?;

        let (code, prefix_len) = decode_varint(&prefixed)?;
        if code != expected_code {
            return Err(SigError::InvalidPublicKey(format!(
                "multicodec code 0x{:x} does not match expected code 0x{:x} for {}",
                code, expected_code, algorithm.as_str()
            )));
        }

        let bytes = prefixed[prefix_len..].to_vec();
        Ok(Self { algorithm, bytes })
    }

    /// Serialize to JSON string.
    pub fn to_json(&self) -> SigResult<String> {
        serde_json::to_string(self)
            .map_err(|e| SigError::Serialization(e.to_string()))
    }

    /// Deserialize from JSON string.
    pub fn from_json(json: &str) -> SigResult<Self> {
        serde_json::from_str(json)
            .map_err(|e| SigError::Serialization(e.to_string()))
    }
}

// ── Secret Key ────────────────────────────────────────────────────────────────

/// A post-quantum secret key with its algorithm tag. Zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SigSecretKey {
    /// The algorithm this key belongs to.
    /// Skipped during zeroization — `SigAlgorithm` is a plain enum with no secret data.
    #[zeroize(skip)]
    pub algorithm: SigAlgorithm,
    /// Raw secret key bytes (zeroized on drop).
    pub bytes: Vec<u8>,
}

impl core::fmt::Debug for SigSecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SigSecretKey {{ algorithm: {:?}, bytes: [REDACTED {} bytes] }}", self.algorithm, self.bytes.len())
    }
}

impl SigSecretKey {
    /// Create a new secret key from raw bytes.
    pub fn new(algorithm: SigAlgorithm, bytes: Vec<u8>) -> Self {
        Self { algorithm, bytes }
    }

    /// Returns the raw bytes of the secret key.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Encode the secret key bytes as base64url (no padding).
    pub fn to_base64url(&self) -> String {
        Base64Url::encode_string(&self.bytes)
    }

    /// Decode a secret key from base64url bytes.
    pub fn from_base64url(algorithm: SigAlgorithm, encoded: &str) -> SigResult<Self> {
        let bytes = Base64Url::decode_vec(encoded)
            .map_err(|e| SigError::Base64Decode(e.to_string()))?;
        Ok(Self { algorithm, bytes })
    }
}

// ── Signature ─────────────────────────────────────────────────────────────────

/// A post-quantum signature with its algorithm tag.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Signature {
    /// The algorithm used to produce this signature.
    pub algorithm: SigAlgorithm,
    /// Raw signature bytes.
    #[serde(
        serialize_with   = "serialize_bytes_base64url",
        deserialize_with = "deserialize_bytes_base64url"
    )]
    pub bytes: Vec<u8>,
}

impl Signature {
    /// Create a new signature from raw bytes.
    pub fn new(algorithm: SigAlgorithm, bytes: Vec<u8>) -> Self {
        Self { algorithm, bytes }
    }

    /// Returns the raw bytes of the signature.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Encode the signature bytes as base64url (no padding).
    pub fn to_base64url(&self) -> String {
        Base64Url::encode_string(&self.bytes)
    }

    /// Decode a signature from base64url bytes.
    pub fn from_base64url(algorithm: SigAlgorithm, encoded: &str) -> SigResult<Self> {
        let bytes = Base64Url::decode_vec(encoded)
            .map_err(|e| SigError::Base64Decode(e.to_string()))?;
        Ok(Self { algorithm, bytes })
    }

    /// Serialize to JSON string (for WASM boundary crossing).
    pub fn to_json(&self) -> SigResult<String> {
        serde_json::to_string(self)
            .map_err(|e| SigError::Serialization(e.to_string()))
    }

    /// Deserialize from JSON string.
    pub fn from_json(json: &str) -> SigResult<Self> {
        serde_json::from_str(json)
            .map_err(|e| SigError::Serialization(e.to_string()))
    }
}

// ── Signed Message Envelope ───────────────────────────────────────────────────

/// A signed message envelope — bundles the message, signature, and public key together.
///
/// Useful for self-contained attestation payloads that can be verified without
/// any external context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedMessage {
    /// The original message bytes (base64url encoded in JSON).
    #[serde(
        serialize_with   = "serialize_bytes_base64url",
        deserialize_with = "deserialize_bytes_base64url"
    )]
    pub message: Vec<u8>,
    /// The signature over the message.
    pub signature: Signature,
    /// The public key that produced the signature.
    pub public_key: SigPublicKey,
    /// Algorithm identifier string (e.g. "ML-DSA-65").
    pub algorithm: String,
}

impl SignedMessage {
    /// Create a new signed message envelope.
    pub fn new(message: Vec<u8>, signature: Signature, public_key: SigPublicKey) -> Self {
        let algorithm = signature.algorithm.as_str().to_string();
        Self { message, signature, public_key, algorithm }
    }

    /// Serialize to JSON string.
    pub fn to_json(&self) -> SigResult<String> {
        serde_json::to_string(self)
            .map_err(|e| SigError::Serialization(e.to_string()))
    }

    /// Deserialize from JSON string.
    pub fn from_json(json: &str) -> SigResult<Self> {
        serde_json::from_str(json)
            .map_err(|e| SigError::Serialization(e.to_string()))
    }
}

// ── Serde Helpers ─────────────────────────────────────────────────────────────

fn serialize_bytes_base64url<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&Base64Url::encode_string(bytes))
}

fn deserialize_bytes_base64url<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    Base64Url::decode_vec(&s).map_err(serde::de::Error::custom)
}
