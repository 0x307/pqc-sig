//! WASM bindings for `pqc-sig` via `wasm-bindgen`.
//!
//! These bindings expose post-quantum signature operations to JavaScript/TypeScript.
//! All byte arrays cross the WASM boundary as `Uint8Array`.
//! All errors are returned as JavaScript `Error` objects (via `Result<T, JsValue>`).
//!
//! # Usage from JavaScript
//! ```javascript
//! import init, {
//!   WasmMlDsa65Keypair,
//!   WasmMlDsa44Keypair,
//!   WasmMlDsa87Keypair,
//!   WasmSlhDsaSha2_128sKeypair,
//!   WasmSlhDsaSha2_192sKeypair,
//!   WasmSlhDsaSha2_256sKeypair,
//!   WasmSlhDsaShake192sKeypair,
//!   WasmSlhDsaShake256sKeypair,
//!   ml_dsa_65_verify,
//! } from './pqc_sig.js';
//!
//! await init();
//!
//! // ML-DSA-65 (recommended)
//! const keypair = new WasmMlDsa65Keypair();
//! const pubKeyBytes = keypair.public_key_bytes();
//! const signature = keypair.sign(new TextEncoder().encode("Hello, world!"));
//! const valid = ml_dsa_65_verify(pubKeyBytes, new TextEncoder().encode("Hello, world!"), signature);
//! ```

extern crate alloc;
use alloc::{string::{String, ToString}, vec::Vec};

use wasm_bindgen::prelude::*;

use crate::fips204::{MlDsa44Keypair, MlDsa65Keypair, MlDsa87Keypair};
use crate::fips205::{
    SlhDsaSha2_128sKeypair, SlhDsaSha2_128fKeypair,
    SlhDsaSha2_192sKeypair, SlhDsaSha2_192fKeypair,
    SlhDsaSha2_256sKeypair, SlhDsaSha2_256fKeypair,
    SlhDsaShake128sKeypair, SlhDsaShake128fKeypair,
    SlhDsaShake192sKeypair, SlhDsaShake192fKeypair,
    SlhDsaShake256sKeypair, SlhDsaShake256fKeypair,
};
use crate::types::{SigAlgorithm, SigPublicKey, Signature};

// ── RNG for WASM ──────────────────────────────────────────────────────────────
// In WASM, we use getrandom which hooks into window.crypto.getRandomValues()
// The `getrandom/js` feature must be enabled (set in Cargo.toml under [features] wasm).

fn wasm_rng() -> rand_core::OsRng {
    rand_core::OsRng
}

// ── Error Conversion ──────────────────────────────────────────────────────────

fn to_js_error(e: crate::error::SigError) -> JsValue {
    JsValue::from_str(&e.to_string())
}

// ── ML-DSA-44 ─────────────────────────────────────────────────────────────────

/// ML-DSA-44 keypair for WASM environments (Security Level 2).
#[wasm_bindgen]
pub struct WasmMlDsa44Keypair {
    inner: MlDsa44Keypair,
}

#[wasm_bindgen]
impl WasmMlDsa44Keypair {
    /// Generate a new ML-DSA-44 keypair using the browser's Web Crypto entropy source.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<WasmMlDsa44Keypair, JsValue> {
        let mut rng = wasm_rng();
        let inner = MlDsa44Keypair::generate(&mut rng).map_err(to_js_error)?;
        Ok(Self { inner })
    }

    /// Returns the public key as raw bytes (1312 bytes).
    #[wasm_bindgen]
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.inner.public_key().bytes
    }

    /// Returns the public key as a base64url string.
    #[wasm_bindgen]
    pub fn public_key_base64url(&self) -> String {
        self.inner.public_key().to_base64url()
    }

    /// Sign a message, returning the signature bytes (2420 bytes).
    #[wasm_bindgen]
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, JsValue> {
        let mut rng = wasm_rng();
        let sig = self.inner.sign(&mut rng, message).map_err(to_js_error)?;
        Ok(sig.bytes)
    }
}

/// Verify an ML-DSA-44 signature.
///
/// Returns `true` if valid, `false` if invalid.
#[wasm_bindgen]
pub fn ml_dsa_44_verify(
    public_key_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> bool {
    let pk = SigPublicKey::new(SigAlgorithm::MlDsa44, public_key_bytes.to_vec());
    let sig = Signature::new(SigAlgorithm::MlDsa44, signature_bytes.to_vec());
    MlDsa44Keypair::verify(&pk, message, &sig).is_ok()
}

// ── ML-DSA-65 ─────────────────────────────────────────────────────────────────

/// ML-DSA-65 keypair for WASM environments (Security Level 3, recommended).
#[wasm_bindgen]
pub struct WasmMlDsa65Keypair {
    inner: MlDsa65Keypair,
}

#[wasm_bindgen]
impl WasmMlDsa65Keypair {
    /// Generate a new ML-DSA-65 keypair using the browser's Web Crypto entropy source.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<WasmMlDsa65Keypair, JsValue> {
        let mut rng = wasm_rng();
        let inner = MlDsa65Keypair::generate(&mut rng).map_err(to_js_error)?;
        Ok(Self { inner })
    }

    /// Returns the public key as raw bytes (1952 bytes).
    #[wasm_bindgen]
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.inner.public_key().bytes
    }

    /// Returns the public key as a base64url string.
    #[wasm_bindgen]
    pub fn public_key_base64url(&self) -> String {
        self.inner.public_key().to_base64url()
    }

    /// Returns the public key as a JSON string (for DID Documents).
    #[wasm_bindgen]
    pub fn public_key_json(&self) -> Result<String, JsValue> {
        self.inner.public_key().to_json().map_err(to_js_error)
    }

    /// Sign a message, returning the signature bytes (3309 bytes).
    #[wasm_bindgen]
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, JsValue> {
        let mut rng = wasm_rng();
        let sig = self.inner.sign(&mut rng, message).map_err(to_js_error)?;
        Ok(sig.bytes)
    }

    /// Sign a message and return the signature as a JSON string.
    #[wasm_bindgen]
    pub fn sign_json(&self, message: &[u8]) -> Result<String, JsValue> {
        let mut rng = wasm_rng();
        let sig = self.inner.sign(&mut rng, message).map_err(to_js_error)?;
        sig.to_json().map_err(to_js_error)
    }
}

/// Verify an ML-DSA-65 signature.
///
/// Returns `true` if valid, `false` if invalid.
#[wasm_bindgen]
pub fn ml_dsa_65_verify(
    public_key_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> bool {
    let pk = SigPublicKey::new(SigAlgorithm::MlDsa65, public_key_bytes.to_vec());
    let sig = Signature::new(SigAlgorithm::MlDsa65, signature_bytes.to_vec());
    MlDsa65Keypair::verify(&pk, message, &sig).is_ok()
}

// ── ML-DSA-87 ─────────────────────────────────────────────────────────────────

/// ML-DSA-87 keypair for WASM environments (Security Level 5).
#[wasm_bindgen]
pub struct WasmMlDsa87Keypair {
    inner: MlDsa87Keypair,
}

#[wasm_bindgen]
impl WasmMlDsa87Keypair {
    /// Generate a new ML-DSA-87 keypair using the browser's Web Crypto entropy source.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<WasmMlDsa87Keypair, JsValue> {
        let mut rng = wasm_rng();
        let inner = MlDsa87Keypair::generate(&mut rng).map_err(to_js_error)?;
        Ok(Self { inner })
    }

    /// Returns the public key as raw bytes (2592 bytes).
    #[wasm_bindgen]
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.inner.public_key().bytes
    }

    /// Returns the public key as a base64url string.
    #[wasm_bindgen]
    pub fn public_key_base64url(&self) -> String {
        self.inner.public_key().to_base64url()
    }

    /// Sign a message, returning the signature bytes (4627 bytes).
    #[wasm_bindgen]
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, JsValue> {
        let mut rng = wasm_rng();
        let sig = self.inner.sign(&mut rng, message).map_err(to_js_error)?;
        Ok(sig.bytes)
    }
}

/// Verify an ML-DSA-87 signature.
///
/// Returns `true` if valid, `false` if invalid.
#[wasm_bindgen]
pub fn ml_dsa_87_verify(
    public_key_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> bool {
    let pk = SigPublicKey::new(SigAlgorithm::MlDsa87, public_key_bytes.to_vec());
    let sig = Signature::new(SigAlgorithm::MlDsa87, signature_bytes.to_vec());
    MlDsa87Keypair::verify(&pk, message, &sig).is_ok()
}

// ── SLH-DSA-SHA2-128s ─────────────────────────────────────────────────────────

/// SLH-DSA-SHA2-128s keypair for WASM environments (Security Level 1, small signatures).
///
/// Note: SLH-DSA signatures are large (7856 bytes for this parameter set).
#[wasm_bindgen]
pub struct WasmSlhDsaSha2_128sKeypair {
    inner: SlhDsaSha2_128sKeypair,
}

#[wasm_bindgen]
impl WasmSlhDsaSha2_128sKeypair {
    /// Generate a new SLH-DSA-SHA2-128s keypair.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<WasmSlhDsaSha2_128sKeypair, JsValue> {
        let mut rng = wasm_rng();
        let inner = SlhDsaSha2_128sKeypair::generate(&mut rng).map_err(to_js_error)?;
        Ok(Self { inner })
    }

    /// Returns the public key as raw bytes (32 bytes).
    #[wasm_bindgen]
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.inner.public_key().bytes
    }

    /// Sign a message, returning the signature bytes (7856 bytes).
    #[wasm_bindgen]
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, JsValue> {
        let mut rng = wasm_rng();
        let sig = self.inner.sign(&mut rng, message).map_err(to_js_error)?;
        Ok(sig.bytes)
    }
}

/// Verify an SLH-DSA-SHA2-128s signature.
#[wasm_bindgen]
pub fn slh_dsa_sha2_128s_verify(
    public_key_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> bool {
    let pk = SigPublicKey::new(SigAlgorithm::SlhDsaSha2_128s, public_key_bytes.to_vec());
    let sig = Signature::new(SigAlgorithm::SlhDsaSha2_128s, signature_bytes.to_vec());
    SlhDsaSha2_128sKeypair::verify(&pk, message, &sig).is_ok()
}

// ── SLH-DSA-SHA2-128f ─────────────────────────────────────────────────────────

/// SLH-DSA-SHA2-128f keypair for WASM environments (Security Level 1, fast signing).
#[wasm_bindgen]
pub struct WasmSlhDsaSha2_128fKeypair {
    inner: SlhDsaSha2_128fKeypair,
}

#[wasm_bindgen]
impl WasmSlhDsaSha2_128fKeypair {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<WasmSlhDsaSha2_128fKeypair, JsValue> {
        let mut rng = wasm_rng();
        let inner = SlhDsaSha2_128fKeypair::generate(&mut rng).map_err(to_js_error)?;
        Ok(Self { inner })
    }
    #[wasm_bindgen]
    pub fn public_key_bytes(&self) -> Vec<u8> { self.inner.public_key().bytes }
    #[wasm_bindgen]
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, JsValue> {
        let mut rng = wasm_rng();
        let sig = self.inner.sign(&mut rng, message).map_err(to_js_error)?;
        Ok(sig.bytes)
    }
}

/// Verify an SLH-DSA-SHA2-128f signature.
#[wasm_bindgen]
pub fn slh_dsa_sha2_128f_verify(public_key_bytes: &[u8], message: &[u8], signature_bytes: &[u8]) -> bool {
    let pk = SigPublicKey::new(SigAlgorithm::SlhDsaSha2_128f, public_key_bytes.to_vec());
    let sig = Signature::new(SigAlgorithm::SlhDsaSha2_128f, signature_bytes.to_vec());
    SlhDsaSha2_128fKeypair::verify(&pk, message, &sig).is_ok()
}

// ── SLH-DSA-SHAKE-128s ────────────────────────────────────────────────────────

/// SLH-DSA-SHAKE-128s keypair for WASM environments (Security Level 1, small signatures).
#[wasm_bindgen]
pub struct WasmSlhDsaShake128sKeypair {
    inner: SlhDsaShake128sKeypair,
}

#[wasm_bindgen]
impl WasmSlhDsaShake128sKeypair {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<WasmSlhDsaShake128sKeypair, JsValue> {
        let mut rng = wasm_rng();
        let inner = SlhDsaShake128sKeypair::generate(&mut rng).map_err(to_js_error)?;
        Ok(Self { inner })
    }
    #[wasm_bindgen]
    pub fn public_key_bytes(&self) -> Vec<u8> { self.inner.public_key().bytes }
    #[wasm_bindgen]
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, JsValue> {
        let mut rng = wasm_rng();
        let sig = self.inner.sign(&mut rng, message).map_err(to_js_error)?;
        Ok(sig.bytes)
    }
}

/// Verify an SLH-DSA-SHAKE-128s signature.
#[wasm_bindgen]
pub fn slh_dsa_shake_128s_verify(public_key_bytes: &[u8], message: &[u8], signature_bytes: &[u8]) -> bool {
    let pk = SigPublicKey::new(SigAlgorithm::SlhDsaShake128s, public_key_bytes.to_vec());
    let sig = Signature::new(SigAlgorithm::SlhDsaShake128s, signature_bytes.to_vec());
    SlhDsaShake128sKeypair::verify(&pk, message, &sig).is_ok()
}

// ── SLH-DSA-SHAKE-128f ────────────────────────────────────────────────────────

/// SLH-DSA-SHAKE-128f keypair for WASM environments (Security Level 1, fast signing).
#[wasm_bindgen]
pub struct WasmSlhDsaShake128fKeypair {
    inner: SlhDsaShake128fKeypair,
}

#[wasm_bindgen]
impl WasmSlhDsaShake128fKeypair {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<WasmSlhDsaShake128fKeypair, JsValue> {
        let mut rng = wasm_rng();
        let inner = SlhDsaShake128fKeypair::generate(&mut rng).map_err(to_js_error)?;
        Ok(Self { inner })
    }
    #[wasm_bindgen]
    pub fn public_key_bytes(&self) -> Vec<u8> { self.inner.public_key().bytes }
    #[wasm_bindgen]
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, JsValue> {
        let mut rng = wasm_rng();
        let sig = self.inner.sign(&mut rng, message).map_err(to_js_error)?;
        Ok(sig.bytes)
    }
}

/// Verify an SLH-DSA-SHAKE-128f signature.
#[wasm_bindgen]
pub fn slh_dsa_shake_128f_verify(public_key_bytes: &[u8], message: &[u8], signature_bytes: &[u8]) -> bool {
    let pk = SigPublicKey::new(SigAlgorithm::SlhDsaShake128f, public_key_bytes.to_vec());
    let sig = Signature::new(SigAlgorithm::SlhDsaShake128f, signature_bytes.to_vec());
    SlhDsaShake128fKeypair::verify(&pk, message, &sig).is_ok()
}

// ── SLH-DSA-SHA2-192s ─────────────────────────────────────────────────────────

/// SLH-DSA-SHA2-192s keypair for WASM environments (Security Level 3, small signatures).
#[wasm_bindgen]
pub struct WasmSlhDsaSha2_192sKeypair {
    inner: SlhDsaSha2_192sKeypair,
}

#[wasm_bindgen]
impl WasmSlhDsaSha2_192sKeypair {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<WasmSlhDsaSha2_192sKeypair, JsValue> {
        let mut rng = wasm_rng();
        let inner = SlhDsaSha2_192sKeypair::generate(&mut rng).map_err(to_js_error)?;
        Ok(Self { inner })
    }
    #[wasm_bindgen]
    pub fn public_key_bytes(&self) -> Vec<u8> { self.inner.public_key().bytes }
    #[wasm_bindgen]
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, JsValue> {
        let mut rng = wasm_rng();
        let sig = self.inner.sign(&mut rng, message).map_err(to_js_error)?;
        Ok(sig.bytes)
    }
}

/// Verify an SLH-DSA-SHA2-192s signature.
#[wasm_bindgen]
pub fn slh_dsa_sha2_192s_verify(public_key_bytes: &[u8], message: &[u8], signature_bytes: &[u8]) -> bool {
    let pk = SigPublicKey::new(SigAlgorithm::SlhDsaSha2_192s, public_key_bytes.to_vec());
    let sig = Signature::new(SigAlgorithm::SlhDsaSha2_192s, signature_bytes.to_vec());
    SlhDsaSha2_192sKeypair::verify(&pk, message, &sig).is_ok()
}

// ── SLH-DSA-SHA2-192f ─────────────────────────────────────────────────────────

/// SLH-DSA-SHA2-192f keypair for WASM environments (Security Level 3, fast signing).
#[wasm_bindgen]
pub struct WasmSlhDsaSha2_192fKeypair {
    inner: SlhDsaSha2_192fKeypair,
}

#[wasm_bindgen]
impl WasmSlhDsaSha2_192fKeypair {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<WasmSlhDsaSha2_192fKeypair, JsValue> {
        let mut rng = wasm_rng();
        let inner = SlhDsaSha2_192fKeypair::generate(&mut rng).map_err(to_js_error)?;
        Ok(Self { inner })
    }
    #[wasm_bindgen]
    pub fn public_key_bytes(&self) -> Vec<u8> { self.inner.public_key().bytes }
    #[wasm_bindgen]
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, JsValue> {
        let mut rng = wasm_rng();
        let sig = self.inner.sign(&mut rng, message).map_err(to_js_error)?;
        Ok(sig.bytes)
    }
}

/// Verify an SLH-DSA-SHA2-192f signature.
#[wasm_bindgen]
pub fn slh_dsa_sha2_192f_verify(public_key_bytes: &[u8], message: &[u8], signature_bytes: &[u8]) -> bool {
    let pk = SigPublicKey::new(SigAlgorithm::SlhDsaSha2_192f, public_key_bytes.to_vec());
    let sig = Signature::new(SigAlgorithm::SlhDsaSha2_192f, signature_bytes.to_vec());
    SlhDsaSha2_192fKeypair::verify(&pk, message, &sig).is_ok()
}

// ── SLH-DSA-SHA2-256s ─────────────────────────────────────────────────────────

/// SLH-DSA-SHA2-256s keypair for WASM environments (Security Level 5, small signatures).
#[wasm_bindgen]
pub struct WasmSlhDsaSha2_256sKeypair {
    inner: SlhDsaSha2_256sKeypair,
}

#[wasm_bindgen]
impl WasmSlhDsaSha2_256sKeypair {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<WasmSlhDsaSha2_256sKeypair, JsValue> {
        let mut rng = wasm_rng();
        let inner = SlhDsaSha2_256sKeypair::generate(&mut rng).map_err(to_js_error)?;
        Ok(Self { inner })
    }
    #[wasm_bindgen]
    pub fn public_key_bytes(&self) -> Vec<u8> { self.inner.public_key().bytes }
    #[wasm_bindgen]
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, JsValue> {
        let mut rng = wasm_rng();
        let sig = self.inner.sign(&mut rng, message).map_err(to_js_error)?;
        Ok(sig.bytes)
    }
}

/// Verify an SLH-DSA-SHA2-256s signature.
#[wasm_bindgen]
pub fn slh_dsa_sha2_256s_verify(public_key_bytes: &[u8], message: &[u8], signature_bytes: &[u8]) -> bool {
    let pk = SigPublicKey::new(SigAlgorithm::SlhDsaSha2_256s, public_key_bytes.to_vec());
    let sig = Signature::new(SigAlgorithm::SlhDsaSha2_256s, signature_bytes.to_vec());
    SlhDsaSha2_256sKeypair::verify(&pk, message, &sig).is_ok()
}

// ── SLH-DSA-SHA2-256f ─────────────────────────────────────────────────────────

/// SLH-DSA-SHA2-256f keypair for WASM environments (Security Level 5, fast signing).
#[wasm_bindgen]
pub struct WasmSlhDsaSha2_256fKeypair {
    inner: SlhDsaSha2_256fKeypair,
}

#[wasm_bindgen]
impl WasmSlhDsaSha2_256fKeypair {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<WasmSlhDsaSha2_256fKeypair, JsValue> {
        let mut rng = wasm_rng();
        let inner = SlhDsaSha2_256fKeypair::generate(&mut rng).map_err(to_js_error)?;
        Ok(Self { inner })
    }
    #[wasm_bindgen]
    pub fn public_key_bytes(&self) -> Vec<u8> { self.inner.public_key().bytes }
    #[wasm_bindgen]
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, JsValue> {
        let mut rng = wasm_rng();
        let sig = self.inner.sign(&mut rng, message).map_err(to_js_error)?;
        Ok(sig.bytes)
    }
}

/// Verify an SLH-DSA-SHA2-256f signature.
#[wasm_bindgen]
pub fn slh_dsa_sha2_256f_verify(public_key_bytes: &[u8], message: &[u8], signature_bytes: &[u8]) -> bool {
    let pk = SigPublicKey::new(SigAlgorithm::SlhDsaSha2_256f, public_key_bytes.to_vec());
    let sig = Signature::new(SigAlgorithm::SlhDsaSha2_256f, signature_bytes.to_vec());
    SlhDsaSha2_256fKeypair::verify(&pk, message, &sig).is_ok()
}

// ── SLH-DSA-SHAKE-192s ────────────────────────────────────────────────────────

/// SLH-DSA-SHAKE-192s keypair for WASM environments (Security Level 3, small signatures).
#[wasm_bindgen]
pub struct WasmSlhDsaShake192sKeypair {
    inner: SlhDsaShake192sKeypair,
}

#[wasm_bindgen]
impl WasmSlhDsaShake192sKeypair {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<WasmSlhDsaShake192sKeypair, JsValue> {
        let mut rng = wasm_rng();
        let inner = SlhDsaShake192sKeypair::generate(&mut rng).map_err(to_js_error)?;
        Ok(Self { inner })
    }
    #[wasm_bindgen]
    pub fn public_key_bytes(&self) -> Vec<u8> { self.inner.public_key().bytes }
    #[wasm_bindgen]
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, JsValue> {
        let mut rng = wasm_rng();
        let sig = self.inner.sign(&mut rng, message).map_err(to_js_error)?;
        Ok(sig.bytes)
    }
}

/// Verify an SLH-DSA-SHAKE-192s signature.
#[wasm_bindgen]
pub fn slh_dsa_shake_192s_verify(public_key_bytes: &[u8], message: &[u8], signature_bytes: &[u8]) -> bool {
    let pk = SigPublicKey::new(SigAlgorithm::SlhDsaShake192s, public_key_bytes.to_vec());
    let sig = Signature::new(SigAlgorithm::SlhDsaShake192s, signature_bytes.to_vec());
    SlhDsaShake192sKeypair::verify(&pk, message, &sig).is_ok()
}

// ── SLH-DSA-SHAKE-192f ────────────────────────────────────────────────────────

/// SLH-DSA-SHAKE-192f keypair for WASM environments (Security Level 3, fast signing).
#[wasm_bindgen]
pub struct WasmSlhDsaShake192fKeypair {
    inner: SlhDsaShake192fKeypair,
}

#[wasm_bindgen]
impl WasmSlhDsaShake192fKeypair {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<WasmSlhDsaShake192fKeypair, JsValue> {
        let mut rng = wasm_rng();
        let inner = SlhDsaShake192fKeypair::generate(&mut rng).map_err(to_js_error)?;
        Ok(Self { inner })
    }
    #[wasm_bindgen]
    pub fn public_key_bytes(&self) -> Vec<u8> { self.inner.public_key().bytes }
    #[wasm_bindgen]
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, JsValue> {
        let mut rng = wasm_rng();
        let sig = self.inner.sign(&mut rng, message).map_err(to_js_error)?;
        Ok(sig.bytes)
    }
}

/// Verify an SLH-DSA-SHAKE-192f signature.
#[wasm_bindgen]
pub fn slh_dsa_shake_192f_verify(public_key_bytes: &[u8], message: &[u8], signature_bytes: &[u8]) -> bool {
    let pk = SigPublicKey::new(SigAlgorithm::SlhDsaShake192f, public_key_bytes.to_vec());
    let sig = Signature::new(SigAlgorithm::SlhDsaShake192f, signature_bytes.to_vec());
    SlhDsaShake192fKeypair::verify(&pk, message, &sig).is_ok()
}

// ── SLH-DSA-SHAKE-256s ────────────────────────────────────────────────────────

/// SLH-DSA-SHAKE-256s keypair for WASM environments (Security Level 5, small signatures).
#[wasm_bindgen]
pub struct WasmSlhDsaShake256sKeypair {
    inner: SlhDsaShake256sKeypair,
}

#[wasm_bindgen]
impl WasmSlhDsaShake256sKeypair {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<WasmSlhDsaShake256sKeypair, JsValue> {
        let mut rng = wasm_rng();
        let inner = SlhDsaShake256sKeypair::generate(&mut rng).map_err(to_js_error)?;
        Ok(Self { inner })
    }
    #[wasm_bindgen]
    pub fn public_key_bytes(&self) -> Vec<u8> { self.inner.public_key().bytes }
    #[wasm_bindgen]
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, JsValue> {
        let mut rng = wasm_rng();
        let sig = self.inner.sign(&mut rng, message).map_err(to_js_error)?;
        Ok(sig.bytes)
    }
}

/// Verify an SLH-DSA-SHAKE-256s signature.
#[wasm_bindgen]
pub fn slh_dsa_shake_256s_verify(public_key_bytes: &[u8], message: &[u8], signature_bytes: &[u8]) -> bool {
    let pk = SigPublicKey::new(SigAlgorithm::SlhDsaShake256s, public_key_bytes.to_vec());
    let sig = Signature::new(SigAlgorithm::SlhDsaShake256s, signature_bytes.to_vec());
    SlhDsaShake256sKeypair::verify(&pk, message, &sig).is_ok()
}

// ── SLH-DSA-SHAKE-256f ────────────────────────────────────────────────────────

/// SLH-DSA-SHAKE-256f keypair for WASM environments (Security Level 5, fast signing).
#[wasm_bindgen]
pub struct WasmSlhDsaShake256fKeypair {
    inner: SlhDsaShake256fKeypair,
}

#[wasm_bindgen]
impl WasmSlhDsaShake256fKeypair {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<WasmSlhDsaShake256fKeypair, JsValue> {
        let mut rng = wasm_rng();
        let inner = SlhDsaShake256fKeypair::generate(&mut rng).map_err(to_js_error)?;
        Ok(Self { inner })
    }
    #[wasm_bindgen]
    pub fn public_key_bytes(&self) -> Vec<u8> { self.inner.public_key().bytes }
    #[wasm_bindgen]
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, JsValue> {
        let mut rng = wasm_rng();
        let sig = self.inner.sign(&mut rng, message).map_err(to_js_error)?;
        Ok(sig.bytes)
    }
}

/// Verify an SLH-DSA-SHAKE-256f signature.
#[wasm_bindgen]
pub fn slh_dsa_shake_256f_verify(public_key_bytes: &[u8], message: &[u8], signature_bytes: &[u8]) -> bool {
    let pk = SigPublicKey::new(SigAlgorithm::SlhDsaShake256f, public_key_bytes.to_vec());
    let sig = Signature::new(SigAlgorithm::SlhDsaShake256f, signature_bytes.to_vec());
    SlhDsaShake256fKeypair::verify(&pk, message, &sig).is_ok()
}

// ── Utility Functions ─────────────────────────────────────────────────────────

/// Returns the crate version string.
#[wasm_bindgen]
pub fn pqc_sig_version() -> String {
    crate::VERSION.into()
}

/// Returns the primary algorithm identifier string.
#[wasm_bindgen]
pub fn primary_algorithm() -> String {
    crate::PRIMARY_ALGORITHM.into()
}

/// Returns the expected public key size in bytes for the given algorithm name.
///
/// Returns 0 for unknown algorithm names.
#[wasm_bindgen]
pub fn public_key_size_for_algorithm(algorithm: &str) -> u32 {
    match algorithm {
        "ML-DSA-44"          => 1312,
        "ML-DSA-65"          => 1952,
        "ML-DSA-87"          => 2592,
        "SLH-DSA-SHA2-128s"  => 32,
        "SLH-DSA-SHA2-128f"  => 32,
        "SLH-DSA-SHA2-192s"  => 48,
        "SLH-DSA-SHA2-192f"  => 48,
        "SLH-DSA-SHA2-256s"  => 64,
        "SLH-DSA-SHA2-256f"  => 64,
        "SLH-DSA-SHAKE-128s" => 32,
        "SLH-DSA-SHAKE-128f" => 32,
        "SLH-DSA-SHAKE-192s" => 48,
        "SLH-DSA-SHAKE-192f" => 48,
        "SLH-DSA-SHAKE-256s" => 64,
        "SLH-DSA-SHAKE-256f" => 64,
        _ => 0,
    }
}

/// Returns the maximum signature size in bytes for the given algorithm name.
///
/// Returns 0 for unknown algorithm names.
#[wasm_bindgen]
pub fn signature_size_for_algorithm(algorithm: &str) -> u32 {
    match algorithm {
        "ML-DSA-44"          => 2420,
        "ML-DSA-65"          => 3309,
        "ML-DSA-87"          => 4627,
        "SLH-DSA-SHA2-128s"  => 7856,
        "SLH-DSA-SHA2-128f"  => 17088,
        "SLH-DSA-SHA2-192s"  => 16224,
        "SLH-DSA-SHA2-192f"  => 35664,
        "SLH-DSA-SHA2-256s"  => 29792,
        "SLH-DSA-SHA2-256f"  => 49856,
        "SLH-DSA-SHAKE-128s" => 7856,
        "SLH-DSA-SHAKE-128f" => 17088,
        "SLH-DSA-SHAKE-192s" => 16224,
        "SLH-DSA-SHAKE-192f" => 35664,
        "SLH-DSA-SHAKE-256s" => 29792,
        "SLH-DSA-SHAKE-256f" => 49856,
        _ => 0,
    }
}
