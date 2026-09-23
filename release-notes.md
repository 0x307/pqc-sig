# pqc-sig Release Notes

## v0.4.1 (2026-09-23)

Adds `BENCHMARKS.md`: measured cost of every operation the crate offers, on a
dedicated-core Intel Xeon Platinum 8488C. **No library code changes** — `src/`
is identical to 0.4.0, so there is nothing to migrate and no behavior to
re-verify.

Signing figures carry a stated resolution limit of about 10%, because each
group signs with a single key and signing cost varies by key. Key generation
and verification are not affected. See `CHANGELOG.md` for detail.

## v0.4.0 (2026-09-09)

Closes five stakeholder-identified adoption gaps (S-1..S-5) blocking SAGP/8gentz-fabric
integration. **Purely additive — no breaking changes, no migration required.**

### Highlights

**S-1: Domain-separated signing.** Every ML-DSA and SLH-DSA keypair (all 15 native FIPS
algorithms) now exposes `sign_ctx`/`sign_ctx_deterministic`/`verify_ctx`, using the FIPS
204/205 `ctx` byte-string parameter natively rather than the hard-coded empty context this
crate previously baked in. This is what lets an agent cryptographically bind a
signature to a specific protocol/relationship (e.g. `"8gentz-agent-v1"` vs.
`"8gentz-fabric-v1"`) so a signature produced for one context can't be replayed as valid in
another — a prerequisite for any multi-tenant or multi-protocol SAGP deployment. FN-DSA gets
the same capability via `fn_dsa::DomainContext`. See
[`examples/domain_separation.rs`](examples/domain_separation.rs).

**S-2: Hybrid bridge for existing classical identities.** `HybridSigner` can now be
constructed from an *already-deployed* Ed25519 secret (`from_ed25519_secret`) or restored
from persisted key material (`from_secret_key_bytes`/`secret_key()`), instead of only
`generate()`-ing a fresh keypair. This removes the practical migration blocker for a fleet
that already has classical identities: agents can add a post-quantum ML-DSA-65 signature
alongside their existing Ed25519 key without re-provisioning identity. `sign_ctx`/
`verify_ctx` bring domain separation to the hybrid combiner too. See
[`examples/hybrid_bridge.rs`](examples/hybrid_bridge.rs) and
[`docs/SAGP_NOTES.md`](docs/SAGP_NOTES.md) for the recommended `PRIMARY_ALGORITHM` (ML-DSA-65)
and Wave-1 accept-hybrid rollout guidance. `hybrid` remains an opt-in feature, off by default.

**S-3: FN-DSA multicodec status, documented.** No code changed here — what changed is
clarity. [`docs/MULTICODEC.md`](docs/MULTICODEC.md) lays out, for all 17 algorithms, exactly
which multicodec codes are upstream-registered (ML-DSA, SLH-DSA) versus this project's own
provisional private-use reservation (FN-DSA `0x307000`/`0x307001`), with a tracking checklist
for when/if multiformats/multicodec registers a real code. Stakeholders integrating FN-DSA
Multikeys into cross-org tooling now have a single authoritative reference for interop scope
instead of having to reverse-engineer it from source comments.

**S-4: Pre-hash signing for large payloads (HashML-DSA / HashSLH-DSA).** `sign_prehash`/
`sign_prehash_deterministic`/`verify_prehash`, spec-conformant with FIPS 204 §5.4 Alg 4/5 and
FIPS 205 §10.2.2 Alg 23/25, let a caller hash a large artifact (a container image, a model
checkpoint, an 8gentz module bundle) themselves and sign only the digest — this crate never
buffers the full payload for signing purposes. Digest strength is enforced against the target
algorithm's security level (`SigError::PreHashTooWeak`), so e.g. SHA-256 is rejected for
ML-DSA-65/87 rather than silently under-securing the signature. See
[`examples/prehash_large_payload.rs`](examples/prehash_large_payload.rs).

**S-5: External, independently-checkable proof.** 132 known-answer test vectors, with key
material sourced from NIST's own ACVP-Server (not self-generated) — and 15 of them verbatim
NIST ACVP `ML-DSA-sigVer` cases, signature and expected result included — are now published under
[`tests/vectors/`](tests/vectors/), executed on every `cargo test`, and shipped inside the
packaged crate so downstream consumers can verify this implementation offline without
depending on any network service. A new WASM CI workflow
([`.github/workflows/wasm.yml`](.github/workflows/wasm.yml)) additionally proves the compiled
WASM artifact behaves identically to the native build, on every push.

### Upgrading from 0.3.x

No code changes are required. Every addition in this release is either:

- a new opt-in method on an existing type (`sign_ctx`, `sign_prehash`, and friends) — existing
  calls to `sign`/`verify` are untouched and byte-identical to before;
- a new opt-in constructor on `HybridSigner` (`from_ed25519_secret`, `from_secret_key_bytes`)
  — `HybridSigner::generate()` still works exactly as before, and `hybrid` is still not a
  default feature (`features = ["hybrid"]` is still required to use any of it); or
- documentation/tooling only (`docs/MULTICODEC.md`, `docs/SAGP_NOTES.md`, KAT vectors, CI).

If you build `pqc-sig-wasm` yourself: it is now version `0.4.0` and exposes 60 new JS
bindings (`sign_ctx`/`sign_prehash` on all 15 bound keypairs, plus free-function
`{alg}_verify_ctx`/`{alg}_verify_prehash`). `verify_ctx`/`verify_prehash` return
`Result<(), JsValue>` rather than `bool` — if you call these *new* functions from JS, check
for a thrown/rejected error rather than a falsy return; the pre-existing `{alg}_verify`
functions are unchanged. If you consume `wit/pqc-sig.wit`, the package name is now
`x307:pqc-sig@0.4.0` (was `@0.1.0`, stale).

### Known limitations

- ML-DSA `sign(rng, ..)`/`sign_ctx`/`sign_prehash` remain **deterministic**: the
  caller-provided `rng` is accepted but currently ignored. Hedged/randomized ML-DSA signing
  needs a `rand_core` 0.6→0.10 adapter for the upstream `ml-dsa` crate — this is a
  pre-existing limitation (`TODO(hedging)`), not new in this release.
- SLH-DSA cannot stream a message by construction — the full message must be buffered before
  signing/verifying. Pre-hash signing (S-4) is the recommended mitigation for large payloads.
- SLH-DSA's published KATs have ACVP-sourced *keys* but self-generated *signatures* — the
  upstream ACVP `SLH-DSA-sigGen`/`sigVer` files (30–38 MB) were not curated in this pass. See
  [`tests/vectors/README.md`](tests/vectors/README.md) for the exact per-vector provenance and
  what's planned next.
- Published KATs cover **7 of the 12 SLH-DSA parameter sets** (all six SHA2 sets plus
  `SHAKE-128s`). `SHAKE-128f`, `SHAKE-192s/f` and `SHAKE-256s/f` have no published vectors in
  this pass — SLH-DSA signing wall-time was the constraint.
- Test coverage is uneven across the SLH-DSA SHAKE sets: **`SHAKE-192s` and `SHAKE-192f` have
  no automated tests**, and `SHAKE-256f` is covered only by a Multikey encoding check that never
  signs or verifies. All three are exposed API and are thin wrappers over the same upstream
  `slh-dsa` generics as the covered sets, but that wiring is not currently asserted by a test.
- Of the 132 published vectors, **15 are verbatim NIST ACVP `ML-DSA-sigVer` cases** (5 each for
  ML-DSA-44/65/87). The other 117 pair ACVP-derived *key material* with signatures this crate
  generated itself, making them round-trip/self-consistency tests rather than independent
  cross-validation. See [`tests/vectors/README.md`](tests/vectors/README.md) for per-vector
  provenance.
- `pqc-sig-wasm` still does not bind FN-DSA or `hybrid` (unchanged from 0.3.x) — only ML-DSA
  and SLH-DSA are exposed to WASM/JS.
- The hybrid bridge's Ed25519-half context framing (`0x00 ‖ len(ctx) ‖ ctx ‖ msg`) is a
  crate-defined convention, not a cross-implementation standard.

### Test Coverage

- **201 tests passing with `--all-features`, 0 failed, 4 ignored** (up from the `0.3.1`
  baseline of 106) — unit tests: 49 (including 9 new pre-hash tests, 10 new hybrid tests, 2
  new ctx tests); `ml_dsa` integration: 40; `slh_dsa` integration: 46; `fn_dsa` integration:
  27; `kat_tests`: 11; `multibase_tests`: 13; `ssi_interop_test`: 7; doctests: 8 passed / 4
  ignored.
- **132 published KAT vectors** across 10 files under [`tests/vectors/`](tests/vectors/)
  — covering 7 of 12 SLH-DSA parameter sets, of which 15 vectors are verbatim NIST ACVP
  sigVer cases — executed by `kat_tests`, byte-reproducible via
  [`examples/gen_kat_vectors.rs`](examples/gen_kat_vectors.rs).
- **22/22 WASM functional tests** via `node test-wasm.mjs` against the `wasm-pack`-built
  `pqc-sig-wasm` artifact.

### Files of interest

- [`src/ctx.rs`](src/ctx.rs), [`src/prehash.rs`](src/prehash.rs), [`src/hybrid.rs`](src/hybrid.rs)
- [`examples/domain_separation.rs`](examples/domain_separation.rs),
  [`examples/prehash_large_payload.rs`](examples/prehash_large_payload.rs),
  [`examples/hybrid_bridge.rs`](examples/hybrid_bridge.rs),
  [`examples/gen_kat_vectors.rs`](examples/gen_kat_vectors.rs)
- [`docs/SAGP_NOTES.md`](docs/SAGP_NOTES.md), [`docs/MULTICODEC.md`](docs/MULTICODEC.md)
- [`tests/vectors/README.md`](tests/vectors/README.md), [`tests/kat_tests.rs`](tests/kat_tests.rs)
- [`wit/pqc-sig.wit`](wit/pqc-sig.wit), [`.github/workflows/wasm.yml`](.github/workflows/wasm.yml)

## v0.2.1 (2026-09-01)

Docs-only fix: README.md and `src/lib.rs`'s doc-comment examples still pinned `pqc-sig =
"0.1"` after the 0.2.0 release. Caught reviewing the published crates.io page — crates.io
READMEs are immutable per version, so this needed a new release rather than an edit.
Bumped all six version pins to `"0.2"`. No code or behavior change.

## v0.2.0 (2026-09-01)

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

### Added: Hybrid Ed25519 + ML-DSA-65 combiner (`hybrid` feature)

`HybridSigner` produces both a classical Ed25519 and a post-quantum ML-DSA-65 signature on
`sign()`; `verify()` requires both to pass, with the failing side identifiable
(`SigError::HybridClassicalFailed` / `HybridPqcFailed`). For bridging classical deployments
to PQC during migration. Pure Rust (`ed25519-dalek`), WASM-compatible, `no_std` + `alloc`.

### Changed: `fndsa` feature migrated from `pqcrypto-falcon` to `fn-dsa` (pure Rust)

Resolves RUSTSEC-2026-0165/0163/0162 (see [`SECURITY.md`](SECURITY.md)) and drops the C-FFI /
non-WASM limitation — `cargo build --target wasm32-unknown-unknown --features fndsa` now
succeeds, and no C compiler is needed to build any feature of this crate.

- `FnDsa512Keypair::generate` / `FnDsa1024Keypair::generate` now take a caller-provided RNG
  (`generate(&mut rng)`), matching this crate's RNG convention everywhere else. Previously used
  `pqcrypto-falcon`'s internal RNG.
- `FnDsa512Keypair::sign` / `FnDsa1024Keypair::sign` now take a caller-provided RNG
  (`sign(&mut rng, message)`) — FN-DSA signing is randomized, unlike ML-DSA.
- FN-DSA secret key wire size changed: 1345 bytes for FN-DSA-512 (was 1281), 2369 bytes for
  FN-DSA-1024 (was 2305). This is `fn-dsa`'s own encoded signing-key format, not the raw NIST
  secret-key size — implementation-defined, the same posture this crate already takes for the
  ML-DSA seed encoding. Public key and signature sizes are unchanged.
- FN-DSA signatures are now a fixed length (666 / 1280 bytes, zero-padded) rather than
  variable-length up to that size.

### Test Coverage

- **106 tests passing with `--features fndsa,hybrid`** (79 with neither feature, 99 with
  `fndsa` only, 86 with `hybrid` only).
- `cargo deny check` (advisories, bans, licenses, sources) passes cleanly with `--all-features`
  — no accepted or ignored findings.
- Verified against live `wasm32-unknown-unknown` builds: `--features fndsa`,
  `--features wasm,fndsa,hybrid`.

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
