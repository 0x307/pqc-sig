# pqc-sig Release Notes

## Unreleased

### BREAKING: `SigPublicKey::to_multibase()` / `from_multibase()` now emit W3C Multikeys

`to_multibase()` previously base58btc-encoded raw public key bytes with no multicodec prefix,
which is not a valid [W3C Multikey](https://www.w3.org/TR/controller-document/#multikey) and
would be rejected by any spec-conformant verifier (e.g. the `ssi` crate).

- Output now carries a [multicodec](https://github.com/multiformats/multicodec) varint prefix
  identifying the key type, per the Multikey spec, for ML-DSA (FIPS 204) and SLH-DSA (FIPS 205)
  keys.
- `to_multibase()` now returns `SigResult<String>` instead of `String` — callers must handle
  the `Result`.
- `from_multibase()` now verifies the embedded multicodec code matches the `algorithm` argument
  and returns an error on mismatch (previously it trusted the caller-supplied algorithm blindly).
- **FN-DSA (FIPS 206 / Falcon) is not supported** by `to_multibase()`/`from_multibase()`: no
  multicodec code is registered for it yet upstream. Both functions return `SigError` for
  `FnDsa512`/`FnDsa1024`. This will be revisited once a code is registered.
- Multibase strings produced by the old code are **not** valid Multikeys and will fail to decode
  under `from_multibase()`. There is no migration path for old-format strings other than
  re-encoding from the raw key bytes.
- Committed test vectors: `tests/multibase_tests.rs`.
- Independently verified: `tests/ssi_interop_test.rs` decodes our output with `multibase`
  (multiformats/rust-multibase) and `ssi-multicodec` (spruceid/ssi, dev-dependency only) and
  confirms the recovered multicodec code and key bytes match what we encoded, for ML-DSA-44/65/87
  and two SLH-DSA parameter sets.

## v0.1.0 (2026-08-01)

### Initial Release

**Post-quantum digital signatures** — standalone, WASM-compatible Rust library.

### Algorithms

| Algorithm | Standard | Status |
|-----------|----------|--------|
| ML-DSA-44 | FIPS 204 | ✅ Implemented |
| ML-DSA-65 | FIPS 204 | ✅ Implemented |
| ML-DSA-87 | FIPS 204 | ✅ Implemented |
| SLH-DSA-SHA2-128s | FIPS 205 | ✅ Implemented |
| SLH-DSA-SHA2-128f | FIPS 205 | ✅ Implemented |
| SLH-DSA-SHA2-192s | FIPS 205 | ✅ Implemented |
| SLH-DSA-SHA2-192f | FIPS 205 | ✅ Implemented |
| SLH-DSA-SHA2-256s | FIPS 205 | ✅ Implemented |
| SLH-DSA-SHA2-256f | FIPS 205 | ✅ Implemented |
| SLH-DSA-SHAKE-128s | FIPS 205 | ✅ Implemented |
| SLH-DSA-SHAKE-128f | FIPS 205 | ✅ Implemented |
| SLH-DSA-SHAKE-192s | FIPS 205 | ✅ Implemented |
| SLH-DSA-SHAKE-192f | FIPS 205 | ✅ Implemented |
| SLH-DSA-SHAKE-256s | FIPS 205 | ✅ Implemented |
| SLH-DSA-SHAKE-256f | FIPS 205 | ✅ Implemented |
| FN-DSA-512 (Falcon) | FIPS 206 (draft) | ✅ Implemented (feature = "fndsa") |
| FN-DSA-1024 (Falcon) | FIPS 206 (draft) | ✅ Implemented (feature = "fndsa") |

### Test Coverage

- **85 tests passing** (66 without Falcon, 85 with `--features fndsa`)
- ML-DSA integration tests: 23
- SLH-DSA integration tests: 20
- FN-DSA integration tests: 15 (feature-gated)
- Unit/smoke tests: 22
- Doc-tests: 5

### WASM Artifacts

- `pqc_sig_bg.wasm` — compiled WebAssembly binary
- `pqc_sig.js` — JavaScript ESM glue module
- `pqc_sig.d.ts` — TypeScript type definitions
- `pqc-sig.wit` — WIT Component Model interface

### Dependencies

- `ml-dsa 0.1.1` — FIPS 204 (pure Rust, RustCrypto)
- `slh-dsa 0.2.0-rc.5` — FIPS 205 (pure Rust, RustCrypto)
- `pqcrypto-falcon 0.3` — FIPS 206 (C FFI, feature-gated)

### Security Properties

- No classical cryptography (PQC-only)
- `no_std` + `alloc` compatible
- Caller-provided RNG (no `OsRng` hardcoding)
- Secret keys zeroized on drop
- All operations return `SigResult<T>` (never panics)
