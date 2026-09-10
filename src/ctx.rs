//! Shared helper for FIPS 204/205/206 domain-separation context strings.
//!
//! FIPS 204 §5.2 (`ML-DSA.Sign`/`ML-DSA.Verify`), FIPS 205 §10.2 (`SLH-DSA.Sign`/`.Verify`),
//! and the FIPS 206 (draft) `DomainContext` construction all encode the context string
//! length in a single byte, which caps it at 255 bytes. `ml-dsa`/`slh-dsa` enforce this
//! themselves but return an opaque `signature::Error`; this module gives callers a
//! structured [`SigError::ContextTooLong`] *before* the call crosses into upstream code,
//! and is shared by every `sign_ctx`/`verify_ctx` implementation in this crate.

use crate::error::{SigError, SigResult};

/// Maximum length, in bytes, of a FIPS 204/205/206 domain-separation context string.
///
/// Enforced by every `sign_ctx`/`sign_ctx_deterministic`/`verify_ctx` method in this crate.
pub const MAX_CONTEXT_LEN: usize = 255;

/// Validate a context string against the shared FIPS 204/205/206 255-byte limit.
///
/// Returns [`SigError::ContextTooLong`] when `ctx.len() > `[`MAX_CONTEXT_LEN`]. Every
/// `sign_ctx`/`sign_ctx_deterministic`/`verify_ctx` method calls this (as `check_ctx`)
/// before delegating to the underlying `ml-dsa`/`slh-dsa`/`fn-dsa` implementation.
pub(crate) fn check_ctx(ctx: &[u8]) -> SigResult<()> {
    if ctx.len() > MAX_CONTEXT_LEN {
        return Err(SigError::ContextTooLong { len: ctx.len() });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    // `vec!` needs an explicit import here: this module's non-test code only ever
    // touches `&[u8]` slices, so unlike `src/hybrid.rs`/`src/fips204/*.rs` etc. it
    // never otherwise links `alloc` — declared locally (unconditionally, like those
    // other modules) rather than relying on `std`'s implicit prelude `vec!`, which
    // isn't in scope without the `std` feature.
    extern crate alloc;
    use alloc::vec;

    #[test]
    fn accepts_empty_and_max_len() {
        assert!(check_ctx(&[]).is_ok());
        assert!(check_ctx(&[0u8; MAX_CONTEXT_LEN]).is_ok());
    }

    #[test]
    fn rejects_over_max_len() {
        let ctx = vec![0u8; MAX_CONTEXT_LEN + 1];
        match check_ctx(&ctx) {
            Err(SigError::ContextTooLong { len }) => assert_eq!(len, MAX_CONTEXT_LEN + 1),
            other => panic!("expected ContextTooLong, got {other:?}"),
        }
    }
}
