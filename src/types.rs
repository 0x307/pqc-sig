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
    /// algorithm's public key, as registered (draft status) in the multicodec table.
    ///
    /// FN-DSA (FIPS 206 / Falcon) has no registered multicodec code as of this writing, so
    /// `to_multibase`/`from_multibase` are not supported for `FnDsa512`/`FnDsa1024`.
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
            SigAlgorithm::FnDsa512 | SigAlgorithm::FnDsa1024 => {
                Err(SigError::InvalidPublicKey(alloc::format!(
                    "{} has no registered multicodec code; multibase encoding is not supported for FN-DSA",
                    self.as_str()
                )))
            }
        }
    }
}

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
    /// Returns an error for algorithms with no registered multicodec code (currently FN-DSA).
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
