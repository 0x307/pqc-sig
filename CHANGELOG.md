# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to the breaking-change and deprecation rules in
[`STABILITY.md`](./STABILITY.md) rather than strict SemVer prior to `1.0.0` — see that
document for what counts as breaking inside `0.x`.

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
