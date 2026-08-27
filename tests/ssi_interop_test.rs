//! Independent-implementation interop tests for `SigPublicKey::to_multibase()`.
//!
//! `tests/multibase_tests.rs` checks our encoder against committed vectors, but those vectors
//! were produced by this crate itself — internally consistent, not independently verified.
//!
//! This file decodes our `to_multibase()` output with two crates we did not write and share no
//! code with:
//! - `multibase` (multiformats/rust-multibase) for the base58btc 'z' layer
//! - `ssi-multicodec` (spruceid/ssi) for the multicodec varint-prefix layer — the same crate
//!   `ssi`'s DID/verification-method machinery uses to parse `Multikey` values
//!
//! If both agree the multicodec code and trailing bytes match what we encoded, the output is a
//! structurally valid Multikey by an implementation other than ours (per P2-04 acceptance
//! criteria). Note `ssi-multicodec` decodes generically by code number — it does not need to
//! recognize ML-DSA/SLH-DSA semantically (it doesn't; those are new draft PQC codes) to confirm
//! the wire format is correct.

use pqc_sig::types::{SigAlgorithm, SigPublicKey};

fn deterministic_bytes(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 256) as u8).collect()
}

/// Decode a `to_multibase()` string with `multibase` + `ssi_multicodec`, and assert the
/// recovered multicodec code and key bytes match what we encoded.
fn assert_independently_valid_multikey(algo: SigAlgorithm) {
    let original_bytes = deterministic_bytes(algo.public_key_size());
    let pk = SigPublicKey::new(algo, original_bytes.clone());
    let multibase_str = pk.to_multibase().expect("our encoder failed");

    // Independent multibase (base58btc) layer.
    let (base, prefixed_bytes) = multibase::decode(&multibase_str)
        .expect("independent multibase decoder rejected our output");
    assert_eq!(base, multibase::Base::Base58Btc, "{:?}", algo);

    // Independent multicodec (varint prefix) layer.
    let multi_encoded = ssi_multicodec::MultiEncoded::new(&prefixed_bytes)
        .expect("independent multicodec decoder rejected our output as malformed");

    let expected_code = algo.multicodec_code().unwrap() as u64;
    assert_eq!(multi_encoded.codec(), expected_code, "multicodec code mismatch for {:?}", algo);
    assert_eq!(multi_encoded.data(), original_bytes.as_slice(), "key bytes mismatch for {:?}", algo);
}

#[test]
fn ml_dsa_44_is_valid_multikey_per_independent_decoder() {
    assert_independently_valid_multikey(SigAlgorithm::MlDsa44);
}

#[test]
fn ml_dsa_65_is_valid_multikey_per_independent_decoder() {
    assert_independently_valid_multikey(SigAlgorithm::MlDsa65);
}

#[test]
fn ml_dsa_87_is_valid_multikey_per_independent_decoder() {
    assert_independently_valid_multikey(SigAlgorithm::MlDsa87);
}

#[test]
fn slh_dsa_sha2_128s_is_valid_multikey_per_independent_decoder() {
    assert_independently_valid_multikey(SigAlgorithm::SlhDsaSha2_128s);
}

#[test]
fn slh_dsa_shake_256f_is_valid_multikey_per_independent_decoder() {
    assert_independently_valid_multikey(SigAlgorithm::SlhDsaShake256f);
}

/// FN-DSA has no registered multicodec code, so `to_multibase()` correctly refuses to produce
/// output rather than emitting a non-conformant Multikey. Nothing for an independent decoder to
/// validate here.
#[test]
fn fn_dsa_has_no_multikey_to_validate() {
    let pk = SigPublicKey::new(SigAlgorithm::FnDsa512, deterministic_bytes(SigAlgorithm::FnDsa512.public_key_size()));
    assert!(pk.to_multibase().is_err());
}
