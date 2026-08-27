# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to the breaking-change and deprecation rules in
[`STABILITY.md`](./STABILITY.md) rather than strict SemVer prior to `1.0.0` — see that
document for what counts as breaking inside `0.x`.

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
