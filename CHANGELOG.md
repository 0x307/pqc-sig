# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to the breaking-change and deprecation rules in
[`STABILITY.md`](./STABILITY.md) rather than strict SemVer prior to `1.0.0` — see that
document for what counts as breaking inside `0.x`.

## [0.3.0] - 2026-09-02

Per `STABILITY.md` §2/§4, this is a breaking release — two independent pieces of work land
together (see "Migration from 0.2.x" below).

### Added

- New sibling crate [`pqc-sig-wasm`](pqc-sig-wasm/) (`publish = false`) — the standalone
  `wasm32-unknown-unknown` cdylib artifact and JS bindings for ML-DSA and SLH-DSA, split out
  of the root crate. Unconditionally supplies `#[global_allocator]`/`#[panic_handler]`, since
  it is always the final linked artifact by construction.
- New CI jobs: `pqc-sig-wasm (wasm32 cdylib artifact)` builds the real WASM artifact with
  `--no-default-features`; `Downstream consumer (no_std + external std leak, wasm32)` builds
  `tests/downstream-consumer-fixture/`, a minimal crate that reproduces the class of defect
  this release fixes — no pre-existing CI job could have caught it, since every one of them
  built the crate by itself rather than from a consumer's build graph.
- **Provisional, `0x307`-reserved private-use multicodec codes for FN-DSA**: `0x307000`
  (`FN-DSA-512`) and `0x307001` (`FN-DSA-1024`). `SigAlgorithm::multicodec_code()` now
  returns `Ok(..)` for both (previously `Err(..)`, since no upstream multiformats/multicodec
  code is registered for FN-DSA/Falcon). `SigPublicKey::to_multibase()` / `from_multibase()`
  therefore now work for FN-DSA public keys, producing valid W3C Multikey output that
  independently-written decoders (`multibase` + `ssi-multicodec`) correctly parse
  structurally — see `tests/ssi_interop_test.rs`. This is a **provisional** reservation, not
  an upstream registration; see `src/types.rs`'s `FN_DSA_PRIVATE_USE_BASE` doc comment for the
  full rationale, interop scope (0x307-controlled systems only, not generic third-party
  multicodec tooling), and the revisit trigger for migrating to a real code if/when
  multiformats/multicodec registers one.
- `SigAlgorithm::is_private_use_multicodec()` — returns `true` for FN-DSA (currently the only
  private-use entries), `false` for the upstream-registered ML-DSA/SLH-DSA codes, so callers
  can flag/log non-standard Multikey output if they care.
- New multibase round-trip tests for FN-DSA-512/1024 in `tests/multibase_tests.rs`
  (round-trip, cross-variant rejection, no collision with registered codes) and new
  independent-decoder structural-validity tests in `tests/ssi_interop_test.rs`.

### Changed

- **BREAKING:** `[lib] crate-type` narrowed from `["cdylib", "rlib"]` to `["rlib"]`. The root
  crate is now a pure library and never the final linked artifact.
- **BREAKING:** the `wasm` feature and `src/wasm.rs` are removed from this crate — that
  surface moved to `pqc-sig-wasm`, it is not duplicated.
- Added "When to choose FN-DSA over ML-DSA" guidance to `README.md`, and corrected its WASM
  compatibility framing (FN-DSA has been pure-Rust and WASM-compatible since `0.2.0`'s
  `fn-dsa` migration).
- `tests/ssi_interop_test.rs`'s `fn_dsa_has_no_multikey_to_validate` test (which asserted
  `to_multibase()` *fails* for FN-DSA) is replaced by
  `fn_dsa_512_is_structurally_valid_multikey_per_independent_decoder` /
  `fn_dsa_1024_is_structurally_valid_multikey_per_independent_decoder`, which assert it
  *succeeds* and independently validates — the old test's premise (no multicodec code exists)
  is what this release changes.

### Migration from 0.2.x

- **Library consumers of `pqc-sig` (the common case): no change needed.** `cargo add
  pqc-sig` / `pqc-sig = "0.3"` is enough, unless you were previously enabling
  `features = ["wasm"]` on `pqc-sig` directly — see below.
- **If you consumed `pqc-sig`'s WASM/JS bindings, or built `pqc-sig` itself with
  `--features wasm`:** that surface moved to the new `pqc-sig-wasm` crate. The compiled JS/TS
  API is unchanged; only the Rust-side crate producing it changed. If you build the WASM
  artifact yourself, point your build at `pqc-sig-wasm/` (or `build-wasm.ps1`) instead of
  `pqc-sig/`.
- **If you called `SigAlgorithm::multicodec_code()`, `SigPublicKey::to_multibase()`, or
  `from_multibase()` on `FnDsa512`/`FnDsa1024` and depended on the `Err` result:** these now
  return `Ok(..)` with a provisional private-use code. Call
  `SigAlgorithm::is_private_use_multicodec()` if you need to distinguish provisional from
  upstream-registered codes in your own logic.

## [0.2.1] - 2026-09-01

### Fixed

- README.md and `src/lib.rs`'s doc-comment code examples still pinned `pqc-sig = "0.1"`.
  Caught reviewing the published `0.2.0` crates.io page — since crates.io READMEs are
  immutable per version, this could only be fixed by a new release. A caret range `"0.1"`
  matches only `0.1.x`, so anyone following Quick Start (or the WASM/`no_std`/hybrid
  examples) on `0.2.0` would have installed the old pre-0.2.0 crate, missing the `fndsa`
  migration and the `hybrid` feature entirely. Docs-only change, not breaking.

## [0.2.0] - 2026-09-01

### Added

- Hybrid Ed25519 + ML-DSA-65 combiner (`hybrid` feature) — `HybridSigner` produces both a
  classical and a post-quantum signature; verification requires both to pass, with the
  failing side identifiable in the error. Pure Rust, WASM-compatible.

### Changed

- `fndsa` feature migrated from `pqcrypto-falcon` (C FFI) to
  [`fn-dsa`](https://crates.io/crates/fn-dsa) (pure Rust). `cargo build --target
  wasm32-unknown-unknown --features fndsa` now succeeds; no C compiler is needed to build any
  feature of this crate. Resolves RUSTSEC-2026-0165/0163/0162.
- **BREAKING:** `FnDsa512Keypair::generate()` / `FnDsa1024Keypair::generate()` now require a
  caller-provided RNG: `generate() -> SigResult<Self>` is now `generate<R: CryptoRng +
  RngCore>(rng: &mut R) -> SigResult<Self>`. Migration: pass `&mut OsRng` (or any
  `CryptoRng + RngCore`) — matches this crate's RNG convention everywhere else;
  `pqcrypto-falcon` previously used its own internal RNG.
- **BREAKING:** `FnDsa512Keypair::sign()` / `FnDsa1024Keypair::sign()` now also take a
  caller-provided RNG: `sign(&self, message: &[u8]) -> SigResult<Signature>` is now
  `sign<R: CryptoRng + RngCore>(&self, rng: &mut R, message: &[u8]) -> SigResult<Signature>`.
  FN-DSA signing is randomized, unlike ML-DSA's deterministic signing.
- **BREAKING:** FN-DSA secret key wire size changed: `SigAlgorithm::secret_key_size()` now
  returns 1345 for `FnDsa512` (was 1281) and 2369 for `FnDsa1024` (was 2305) — `fn-dsa`'s own
  encoded signing-key format, implementation-defined like the existing ML-DSA seed encoding.
  A secret key serialized before this change cannot be loaded after it; regenerate keypairs.
  Public key and signature sizes are unchanged.

## [0.1.0] - 2026-08-27

### Added

- Initial release: ML-DSA-44/65/87 (FIPS 204), all 12 SLH-DSA parameter sets (FIPS 205), and
  FN-DSA-512/1024 (FIPS 206 draft, `fndsa` feature) — 17 algorithms, 79 tests passing (lib
  unit tests, per-algorithm integration tests, Multikey encoding tests, and independent
  multicodec interop tests, plus doctests).
- WASM-compatible builds (`wasm` feature) for ML-DSA and SLH-DSA, with a WIT Component Model
  interface at `wit/pqc-sig.wit`.
- `no_std` + `alloc` support, caller-provided RNG, secret keys zeroized on drop.
- `SigPublicKey::to_multibase()` / `from_multibase()` emit valid [W3C
  Multikeys](https://www.w3.org/TR/controller-document/#multikey) — output carries a
  [multicodec](https://github.com/multiformats/multicodec) varint prefix identifying the key
  type, for ML-DSA and SLH-DSA keys. `to_multibase()` returns `SigResult<String>`;
  `from_multibase()` verifies the embedded multicodec code matches the `algorithm` argument.
  FN-DSA (FIPS 206 / Falcon) is not supported by either function — no multicodec code is
  registered for it upstream yet.
- CI: clean-room build verification (`.github/workflows/ci.yml`) — fresh checkout, no cached
  toolchain/registry/build state, on every push to `main` and every pull request. Builds and
  tests default features and `--all-features`, and separately builds/tests the packaged
  `cargo package` artifact under both.
- Program artifacts: `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, `STABILITY.md`,
  issue templates, `LICENSE-MIT` / `LICENSE-APACHE`.
- Dependency scanning: `deny.toml` and `.github/workflows/cargo-deny.yml` — `cargo-deny`
  advisories/bans/licenses/sources on every push to `main`, every pull request, and weekly,
  with a failing scheduled run opening a tracking issue. Deliberately a separate workflow
  from `ci.yml` and not a required check: the `advisories` check is expected to fail on the
  archived-upstream PQClean advisories behind the non-default `fndsa` feature, which are
  documented as accepted in `SECURITY.md` rather than suppressed.

See [release-notes.md](release-notes.md) for full detail, including how the Multikey output
was independently verified against `multibase` and `ssi-multicodec`.
