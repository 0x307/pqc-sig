# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to the breaking-change and deprecation rules in
[`STABILITY.md`](./STABILITY.md) rather than strict SemVer prior to `1.0.0` — see that
document for what counts as breaking inside `0.x`.

## [0.2.0] - 2026-09-01

### Added

- **Provisional, `0x307`-reserved private-use multicodec codes for FN-DSA**: `0x307000`
  (`FN-DSA-512`) and `0x307001` (`FN-DSA-1024`). `SigAlgorithm::multicodec_code()` now
  returns `Ok(..)` for both (previously `Err(..)` in 0.1.0, since no upstream
  multiformats/multicodec code is registered for FN-DSA/Falcon). `SigPublicKey::to_multibase()`
  / `from_multibase()` therefore now work for FN-DSA public keys, producing valid W3C
  Multikey output that independently-written decoders (`multibase` + `ssi-multicodec`)
  correctly parse structurally — see `tests/ssi_interop_test.rs`. This is a **provisional**
  reservation, not an upstream registration; see `src/types.rs`'s `FN_DSA_PRIVATE_USE_BASE`
  doc comment for the full rationale, interop scope (0x307-controlled systems only, not
  generic third-party multicodec tooling), and the revisit trigger for migrating to a real
  code if/when multiformats/multicodec registers one.
- `SigAlgorithm::is_private_use_multicodec()` — returns `true` for FN-DSA (currently the only
  private-use entries), `false` for the upstream-registered ML-DSA/SLH-DSA codes, so callers
  can flag/log non-standard Multikey output if they care.
- New multibase round-trip tests for FN-DSA-512/1024 in `tests/multibase_tests.rs`
  (round-trip, cross-variant rejection, no collision with registered codes) and new
  independent-decoder structural-validity tests in `tests/ssi_interop_test.rs`.

### Changed

- Documentation clarification: FN-DSA-512/1024 (`fndsa` feature) is production-usable today
  (native targets only, C FFI via `pqcrypto-falcon`, not WASM-compatible) — previous wording
  could be read as more provisional than the shipped, tested implementation warrants. No
  changes to `fips206::FnDsa512Keypair`/`FnDsa1024Keypair` signing/verification behavior.
- Added "When to choose FN-DSA over ML-DSA" guidance to `README.md`.
- `tests/ssi_interop_test.rs`'s `fn_dsa_has_no_multikey_to_validate` test (which asserted
  `to_multibase()` *fails* for FN-DSA) is replaced by
  `fn_dsa_512_is_structurally_valid_multikey_per_independent_decoder` /
  `fn_dsa_1024_is_structurally_valid_multikey_per_independent_decoder`, which assert it
  *succeeds* and independently validates — the old test's premise (no multicodec code exists)
  is what this release changes.

### Not changed (no breaking changes in this release)

- `SigAlgorithm`, `fips204`/`fips205`/`fips206` public APIs are otherwise unchanged from
  0.1.0. Turning `multicodec_code()`'s FN-DSA arms from `Err` to `Ok` is additive per
  `STABILITY.md` §2 ("adding a new public function/return value that previously errored is
  not breaking unless callers specifically depended on the error") — nothing in 0.1.0 could
  have depended on this error being permanent, since it was always documented as "not yet
  supported," not "will never be supported."
- FN-DSA's multicodec code is **not** an upstream multiformats/multicodec registration — it
  remains a 0x307-internal provisional reservation, tracked as an open revisit trigger, not
  resolved in this release.

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
