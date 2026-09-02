//! Multibase / W3C Multikey encoding tests for `SigPublicKey::to_multibase`.
//!
//! Test vectors are fixed (deterministic key bytes, not randomly generated) so they can be
//! reused independently — e.g. by the cross-implementation vector runner (P7-02/P7-04) — to
//! validate that any implementation produces the same multicodec-prefixed, base58btc-encoded
//! output for a given algorithm and key.
//!
//! Vectors were generated with this crate's own `to_multibase()` (the varint prefix was
//! hand-verified against the multiformats unsigned-varint spec; base58btc encoding is provided
//! by the independently-maintained `bs58` crate). If these constants ever change, that is a
//! breaking change to the wire format.

use pqc_sig::types::{SigAlgorithm, SigPublicKey};

/// Deterministic, non-random key bytes: byte `i` has value `i % 256`.
fn deterministic_bytes(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 256) as u8).collect()
}

/// (algorithm, multicodec code, expected multibase string for `deterministic_bytes(public_key_size)`)
const VECTORS: &[(SigAlgorithm, u32, &str)] = &[
    (SigAlgorithm::MlDsa44, 0x1210, "z4sdZS9j8G57yMytc2KCRSTFwJoWRRBGXv5eacfrutr8uAsSG7bmZ5fDdKWY6kWuH1H3RtG4rdAqwB8kwtp5fgnSqgrwjLsphTn1PmntK43WUhk2GZdQzmeNEh32UkWBHC8oK41U3WmqHJL42MsJnXgMpX4baRjnEC8rh3o7NkWRjTcsHMqYLEjqYycYdH43dAYs2VNyWq8HWJ4581uKicoS2E6iQc9gKPAVwtH1XrBE6MZXkJZ7hmbtgdbftj1Lh8kzRPajEobTzFwv4ZPaq4oWA1iXSJdQ7mTTkhND8BG3wTcxTYVEaLoVMtbzjF4V8cLvFSUCFoeotkjXW1wBPFKMNjcPxMgcXhzYbkynHGn1X36N2JUFAywS5fX5FiEFxip68uFyBJ1Pf1wydwkG7FWZmLjibnqtqL3xcsScq4iPimbgEXZBCYznfDFSzofLDW3gGhxkGgp8F6KpTsqDaTsRCCRGcQoQB51cJEQrMsBtvPqLQ2CtbXTWq1gxXuMPhbMLU4fFvXp3ydASvbS8WeK6ukw8rsV3GqF9yucTvCRvz7n1Yu8bSNRwwgh7jXucFYZ91CTGrKow6b3F7rD1ESxCA9GTiW1LMa3SHykxXYzwacurrp48zhq5mkx8CU52SbpA1pvX9JoCxCiCtfF8Jt996VQZVm5RoE7QBVk7EMM8QQSTUcJbBRzvq5Cqs3DdGMHK5nDNFbNd4t6n3y9VuZRWsi63AgQemm1bQxZSotDkLnpwcMUQV3d2PT8JjteRHyeWoUh5PoappkjncdT3nbtk27f1N3e1XDQpaAq26nnxgZhUciyC4rPzZj9cnexuJmwEdFntub5VqogxuTss78iNrrxtghd5J3imPsvVDkgCqBqH5yjcUF5ScEjAyv74zNiJWe32ygX56LXZrC5EDQLgJVjsBdUtJ8hzt4o1j7yuRr5G9tPH8qYmpoLNR9fwtPWFcJmKhxBEF4r6qgeuVoVtUgSLKpKbVujBSWSYCDFnuVht8VbLnKo66XBT1v1TavjhuSjPcCEAHJKLBFEkzGv8574REMNpVD9pUDrLDnCcbrbX9r8t7id4CL1ZgTNgvnD5iVq6T7TcPtkCF8Td31c8k2z1zoAn9e4HUbBBYGWTzLtkERzZTB9zEKnrwCC4ABiaDRa5vMyLZDMsEKgxfZnhvyUjGN14zAE2QkqP5QKFfCpGrYigftuvQWsSRv3sWsYV7Tb2rtMJMQuxVtkEU4QYwoW8vENorQBLnoh94ukxrKF6ri3tiwxk7j1ErYpX3Dp9cdFDaV1dHs7hBMDBR7N18wcVTFrnmonNDW8hHTeGcQzUnTk6BJUwkcikYWK1cHdaVGFDe5i3VxM9YG3i7Si2sb65cYzbNTzvsUTb8bMyr13rCZhEBxNza9Nnq2LJz3H3gsxiDqLCuzb8cu3rSNXNhA5d7pyyngwZymCGQ91MefcHUNqSADXbdZ8CZWPLAVGFWFXRJVtnWjhhyXJaD8kHc5BSPmRPwHQhMJSD3ZCLnWNhJJzN4dDGQAKAJ7ACasuZDAGiipTUDb14U1pAR5MXuAh4w2HNz8qXpZMmDjrLG7q1VtaZDcPmWNt5K3DjQZTFp8KiUCDMAry823GGMWBmPzZftV47QkXVbjcezmERD2SbsgESSXQMeog4E3zHSpJagNWeTMzrCpHW1QzrNqNtqQtaEzoEHAseWfYD4VrsAygnyKSYnv8HKBuhbUTh7qK6RcxtpohQXv7gKu2f3tdB5ojQueeTGbH4G59cTBjkngAdQkZunArDEoSHyvFNUwJe"),
    (SigAlgorithm::MlDsa65, 0x1211, "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"),
    (SigAlgorithm::MlDsa87, 0x1212, "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"),
    (SigAlgorithm::SlhDsaSha2_128s, 0x1220, "z4cyMdt7S6hdzXCoAMouetqUmUG2MZV5DTmmAZMWg5Hu1swU"),
    (SigAlgorithm::SlhDsaShake128s, 0x1221, "z4eHQQxzW39DEbyXBUGqopHNHybYKzDovjqxybYm1tcPDix6"),
    (SigAlgorithm::SlhDsaSha2_128f, 0x1222, "z4fbTC3sZyanUgkFCajmxjjFpUw4JQxYe1vAndk1MhvsRZxi"),
    (SigAlgorithm::SlhDsaShake128f, 0x1223, "z4guVy8kdv2MimWyDhCi7fB9LzGaGqhHMHzNbfwFhXFMdQyL"),
    (SigAlgorithm::SlhDsaSha2_192s, 0x1224, "z32JQvtEsL5eRHjzrpRr5Hf1o3MAHMyQbZhy6cFY2jMnrWZ6XLHCfdDTKKmArTq8rAwcgE"),
    (SigAlgorithm::SlhDsaShake192s, 0x1225, "z331rxFUnh9Nywj6LxeZUn462Dw1mpG6QfctQha2z66wj1Nasv6iZXWhvVDkM7FZPDuV3k"),
    (SigAlgorithm::SlhDsaSha2_192f, 0x1226, "z33jJycii4D7YbiBq6sGtGTAFQWsGGYnDmXointXwSr6bWC5EVvETRoxXegKqkfyvGsMRG"),
    (SigAlgorithm::SlhDsaShake192f, 0x1227, "z34SkzyxdRGr7FhHKF5zHkrEUb6ikiqU2sSj2tD2tobFU11Zb5jkML7D8p8uLQ6QTKqDnn"),
    (SigAlgorithm::SlhDsaSha2_256s, 0x1228, "z28VTP8wYgh2wHyNZ5y5TVEXBMNpDZGoCnxHA5npdRfTLCkcMShUHCtZXvAs2MX425GsFhw37dnTpcaKikBDCZU6qK7k"),
    (SigAlgorithm::SlhDsaShake256s, 0x1229, "z28t3f4XMTETbt6GqNbm1LXNXNfAZG18sgPfcUW9SzSypzL8sQsFLVr33ZXd5J7iRdJ3WTJ5wk5JTZvewwSqy5UqX7yg"),
    (SigAlgorithm::SlhDsaSha2_256f, 0x122a, "z29Gdvz7ADmtGUDB7fESZBpDsPwWtxjUYZq44sDUGZEWKmufPP32PnoWZCtP8EiNqBKDmCf8mrN96XGzB8iUjbVaCvqc"),
    (SigAlgorithm::SlhDsaShake256f, 0x122b, "z29fECugxzKJw4L5Pws87375DRDsEfTpDTGSXFvo6822pZVBuMCoT5kz4rF9BBK3EjLQ1x2BbxeyjUdKQKz7W7WJtjhY"),
];

#[test]
fn multicodec_codes_match_registered_draft_values() {
    for (algo, code, _) in VECTORS {
        assert_eq!(algo.multicodec_code().unwrap(), *code, "{:?}", algo);
    }
}

#[test]
fn multibase_vectors_match_committed_output() {
    for (algo, _, expected) in VECTORS {
        let pk = SigPublicKey::new(*algo, deterministic_bytes(algo.public_key_size()));
        let encoded = pk.to_multibase().expect("encode failed");
        assert_eq!(&encoded, expected, "{:?}", algo);
    }
}

#[test]
fn multibase_vectors_round_trip() {
    for (algo, _, expected) in VECTORS {
        let decoded = SigPublicKey::from_multibase(*algo, expected).expect("decode failed");
        assert_eq!(decoded.bytes, deterministic_bytes(algo.public_key_size()), "{:?}", algo);
    }
}

#[test]
fn multibase_rejects_wrong_algorithm() {
    let pk = SigPublicKey::new(SigAlgorithm::MlDsa44, deterministic_bytes(SigAlgorithm::MlDsa44.public_key_size()));
    let encoded = pk.to_multibase().expect("encode failed");
    // Same key material, decoded as a different algorithm — the multicodec code embedded in
    // the multibase string won't match what MlDsa65 expects.
    let err = SigPublicKey::from_multibase(SigAlgorithm::MlDsa65, &encoded);
    assert!(err.is_err());
}

#[test]
fn multibase_rejects_bad_base58() {
    let err = SigPublicKey::from_multibase(SigAlgorithm::MlDsa44, "znot-valid-base58!!!");
    assert!(err.is_err());
}

#[test]
fn multibase_rejects_missing_z_prefix() {
    let err = SigPublicKey::from_multibase(SigAlgorithm::MlDsa44, "abc123");
    assert!(err.is_err());
}

// ── FN-DSA — provisional 0x307 private-use multicodec range ──────────────────
//
// FN-DSA now has a working (though provisional, non-upstream-registered)
// multicodec code -- see `SigAlgorithm::FN_DSA_PRIVATE_USE_BASE`'s doc comment
// in src/types.rs for the full rationale. These tests exercise the same
// to_multibase()/from_multibase() round-trip as the registered-code
// algorithms above, plus the `is_private_use_multicodec()` flag.

#[test]
fn fn_dsa_512_multicodec_code_is_private_use_base() {
    assert_eq!(SigAlgorithm::FnDsa512.multicodec_code().unwrap(), 0x307000);
    assert!(SigAlgorithm::FnDsa512.is_private_use_multicodec());
}

#[test]
fn fn_dsa_1024_multicodec_code_is_private_use_base_plus_one() {
    assert_eq!(SigAlgorithm::FnDsa1024.multicodec_code().unwrap(), 0x307001);
    assert!(SigAlgorithm::FnDsa1024.is_private_use_multicodec());
}

#[test]
fn registered_algorithms_are_not_private_use() {
    for algo in [
        SigAlgorithm::MlDsa44, SigAlgorithm::MlDsa65, SigAlgorithm::MlDsa87,
        SigAlgorithm::SlhDsaSha2_128s, SigAlgorithm::SlhDsaShake256f,
    ] {
        assert!(!algo.is_private_use_multicodec(), "{:?}", algo);
    }
}

#[test]
fn fn_dsa_512_multibase_roundtrip() {
    let bytes = deterministic_bytes(SigAlgorithm::FnDsa512.public_key_size());
    let pk = SigPublicKey::new(SigAlgorithm::FnDsa512, bytes.clone());
    let encoded = pk.to_multibase().expect("FN-DSA-512 encode must succeed (provisional code)");
    assert!(encoded.starts_with('z'));

    let decoded = SigPublicKey::from_multibase(SigAlgorithm::FnDsa512, &encoded)
        .expect("FN-DSA-512 decode must succeed");
    assert_eq!(decoded.bytes, bytes);
}

#[test]
fn fn_dsa_1024_multibase_roundtrip() {
    let bytes = deterministic_bytes(SigAlgorithm::FnDsa1024.public_key_size());
    let pk = SigPublicKey::new(SigAlgorithm::FnDsa1024, bytes.clone());
    let encoded = pk.to_multibase().expect("FN-DSA-1024 encode must succeed (provisional code)");
    assert!(encoded.starts_with('z'));

    let decoded = SigPublicKey::from_multibase(SigAlgorithm::FnDsa1024, &encoded)
        .expect("FN-DSA-1024 decode must succeed");
    assert_eq!(decoded.bytes, bytes);
}

#[test]
fn fn_dsa_multibase_rejects_wrong_variant() {
    // FN-DSA-512 bytes encoded, then decoded as FN-DSA-1024 -- the embedded
    // multicodec code (0x307000) won't match FN-DSA-1024's (0x307001).
    let pk = SigPublicKey::new(SigAlgorithm::FnDsa512, deterministic_bytes(SigAlgorithm::FnDsa512.public_key_size()));
    let encoded = pk.to_multibase().expect("encode failed");
    let err = SigPublicKey::from_multibase(SigAlgorithm::FnDsa1024, &encoded);
    assert!(err.is_err());
}

#[test]
fn fn_dsa_multibase_does_not_collide_with_registered_codes() {
    // Sanity check that the provisional 0x307000/0x307001 codes can never be
    // confused with any of the registered ML-DSA/SLH-DSA codes (0x1210-0x122b)
    // at the varint level -- decoding a registered-code multibase string as
    // FN-DSA (or vice versa) must fail, not silently misinterpret.
    let ml_dsa_pk = SigPublicKey::new(SigAlgorithm::MlDsa44, deterministic_bytes(SigAlgorithm::MlDsa44.public_key_size()));
    let ml_dsa_encoded = ml_dsa_pk.to_multibase().expect("encode failed");
    assert!(SigPublicKey::from_multibase(SigAlgorithm::FnDsa512, &ml_dsa_encoded).is_err());

    let fn_dsa_pk = SigPublicKey::new(SigAlgorithm::FnDsa512, deterministic_bytes(SigAlgorithm::FnDsa512.public_key_size()));
    let fn_dsa_encoded = fn_dsa_pk.to_multibase().expect("encode failed");
    assert!(SigPublicKey::from_multibase(SigAlgorithm::MlDsa44, &fn_dsa_encoded).is_err());
}
