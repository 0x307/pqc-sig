# pqc-sig

> **Tier:** Production · **MSRV:** 1.85 · **License:** MIT OR Apache-2.0 · Not independently audited, see [the crate family](#the-0x307-crate-family)

**Post-quantum digital signatures** — a standalone, WASM-compatible Rust library implementing NIST-standardized post-quantum signature algorithms.

[![CI](https://github.com/0x307/pqc-sig/actions/workflows/ci.yml/badge.svg)](https://github.com/0x307/pqc-sig/actions/workflows/ci.yml)
[![wasm](https://github.com/0x307/pqc-sig/actions/workflows/wasm.yml/badge.svg)](https://github.com/0x307/pqc-sig/actions/workflows/wasm.yml)
[![cargo-deny](https://github.com/0x307/pqc-sig/actions/workflows/cargo-deny.yml/badge.svg)](https://github.com/0x307/pqc-sig/actions/workflows/cargo-deny.yml)
[![crates.io](https://img.shields.io/crates/v/pqc-sig.svg)](https://crates.io/crates/pqc-sig)
[![docs.rs](https://docs.rs/pqc-sig/badge.svg)](https://docs.rs/pqc-sig)
[![MSRV](https://img.shields.io/badge/MSRV-1.85-blue.svg)](#build-requirements)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![FIPS 204](https://img.shields.io/badge/FIPS-204%20ML--DSA-green.svg)](https://csrc.nist.gov/pubs/fips/204/final)
[![FIPS 205](https://img.shields.io/badge/FIPS-205%20SLH--DSA-green.svg)](https://csrc.nist.gov/pubs/fips/205/final)
[![FIPS 206](https://img.shields.io/badge/FIPS-206%20FN--DSA-orange.svg)](https://csrc.nist.gov/pubs/fips/206/ipd)

> **Reading the badges:** **CI** is the build-and-test signal — it should be green, and a red
> one means something is actually broken. **wasm** builds the core crate for
> `wasm32-unknown-unknown`, runs `wasm-pack build` on the sibling `pqc-sig-wasm` crate, and
> executes the [`test-wasm.mjs`](test-wasm.mjs) functional suite under Node — see
> [`.github/workflows/wasm.yml`](.github/workflows/wasm.yml). **cargo-deny** is the
> dependency-advisory signal — also expected green. It previously carried an
> accepted-and-documented exception (the optional `fndsa` feature depended on the now-archived
> `pqcrypto-falcon`); that dependency was migrated to a pure-Rust, actively-maintained
> replacement, so there is currently nothing accepted or suppressed — see
> [`SECURITY.md`](SECURITY.md#known-and-accepted-advisories).

**Verification:** 132 known-answer test vectors are published in
[`tests/vectors/`](tests/vectors/) (ML-DSA-44/65/87 and 7 SLH-DSA parameter sets; keys and
`sigVer` cases sourced from [NIST ACVP-Server](https://github.com/usnistgov/ACVP-Server),
signatures self-generated deterministically by this crate over that externally-sourced key
material — see [`tests/vectors/README.md`](tests/vectors/README.md) for the exact,
per-vector provenance) and executed on every CI run via
[`tests/kat_tests.rs`](tests/kat_tests.rs).

## What runs today vs. what is designed

**Runs today:**

- ML-DSA-44/65/87 (FIPS 204) and all 12 SLH-DSA parameter sets (FIPS 205) — pure Rust,
  `no_std` + `alloc`, directly compilable to `wasm32-unknown-unknown`, keygen/sign/verify
  covered by integration tests.
- FN-DSA-512/1024 (Falcon, FIPS 206 draft), gated behind the `fndsa` feature flag — pure
  Rust via the `fn-dsa` crate, `no_std` + `alloc`, directly compilable to
  `wasm32-unknown-unknown`. No C compiler needed.
- Hybrid Ed25519 + ML-DSA-65, gated behind the `hybrid` feature flag — `HybridSigner`
  combines a classical and a post-quantum signature; verification requires both to pass.
  For bridging classical deployments to PQC during migration. Pure Rust, WASM-compatible.
- `SigPublicKey::to_multibase()` / `from_multibase()` — W3C Multikey encoding for **all 17**
  algorithms, including FN-DSA. ML-DSA/SLH-DSA use officially registered (draft-status)
  multicodec codes, independently verified against the `multibase` and `ssi-multicodec`
  crates (see [`tests/ssi_interop_test.rs`](tests/ssi_interop_test.rs)).

  > **⚠️ FN-DSA Multikey codes are provisional, not upstream-registered.** `to_multibase()`/
  > `from_multibase()` encode FN-DSA-512/1024 public keys using a private-use multicodec code
  > this project self-assigned (`0x307000`/`0x307001`), because
  > [multiformats/multicodec](https://github.com/multiformats/multicodec) has no registered
  > code for FN-DSA/Falcon as of this writing (checked against the live table; no open PR or
  > issue for it either). `SigAlgorithm::is_private_use_multicodec()` flags this at runtime so
  > callers can warn when they're producing a non-standard Multikey. **Interop scope:
  > 0x307-controlled systems only** — a generic third-party multicodec decoder will not
  > recognize `0x307000`/`0x307001` as FN-DSA. **Revisit trigger:** if/when
  > `multiformats/multicodec` merges a real FN-DSA/Falcon code, `multicodec_code()` migrates to
  > it in a follow-up minor release (tracked in [`src/types.rs`](src/types.rs)'s
  > `FN_DSA_PRIVATE_USE_BASE` doc comment, which has the full rationale). See
  > [`docs/MULTICODEC.md`](docs/MULTICODEC.md) for the full code table (registered vs.
  > provisional status for every algorithm) and the upstream-registration tracking checklist.

### FN-DSA status

FN-DSA (Falcon) support is **optional** — enable it with the `fndsa` feature flag; it is
never compiled into the default build. [FIPS 206](https://csrc.nist.gov/pubs/fips/206/ipd)
itself is a NIST **draft** standard, not yet finalized, and FN-DSA's Multikey/DID Document
multicodec codes (`0x307000`/`0x307001`) are **provisional, private-use** codes this project
self-assigned — see [`docs/MULTICODEC.md`](docs/MULTICODEC.md) for the full rationale and
tracking status. **Never use FN-DSA as a default signature algorithm for interop purposes**
— [`PRIMARY_ALGORITHM`](src/lib.rs) (`ML-DSA-65`) is the only algorithm this crate
designates as a default, and it uses a registered multicodec code.
- Standalone WASM/JS bindings for ML-DSA and SLH-DSA live in the sibling
  [`pqc-sig-wasm`](pqc-sig-wasm/) crate (see [WASM Usage](#wasm-usage) below) — this crate
  itself is a pure library (`rlib`-only) and is never the final linked WASM artifact. FN-DSA
  and the hybrid combiner have no WASM *bindings* yet (though both compile to `wasm32` as a
  library dependency — see above).
- A WIT Component Model interface at [`wit/pqc-sig.wit`](wit/pqc-sig.wit) describing the
  ML-DSA and SLH-DSA interfaces for non-Rust WASM runtimes.
- CI (`.github/workflows/ci.yml`) builds and tests both default features and `--all-features`
  on every push/PR, including against the packaged `cargo package` artifact, the
  `pqc-sig-wasm` cdylib artifact, and a downstream-consumer fixture that would otherwise mask
  a `no_std`/`std`-leak regression (see [Continuous Integration](#continuous-integration)).

**Designed, not yet implemented / provisional:**

- FIPS 206 itself is a NIST **draft** standard, not yet finalized (see the FN-DSA badge above)
  — the implementation tracks the draft and may need breaking changes once it's finalized.
- MSRV, `unsafe` code policy, and docs.rs metadata are now stated below (see
  [Build Requirements](#build-requirements) and [Safety](#safety)).


## Performance

Measured, not estimated. Every figure in [`BENCHMARKS.md`](BENCHMARKS.md)
is generated by [`benches/signatures.rs`](benches/signatures.rs) in the same commit, with the CPU,
toolchain and build profile stated beside it.

There are no deterministic stand-ins, no mock adapters and no stub backends
anywhere in this crate, so there is no configuration in which a benchmark
measures a hash instead of a lattice. FN-DSA sits behind a feature and the
harness **panics** rather than skipping when it is off, because a run that
quietly measures nothing still reports success.

Reproduce it:

```bash
cargo bench --features fndsa --bench signatures
```

## When to choose FN-DSA over ML-DSA

Both are NIST post-quantum signature standards; the choice is a tradeoff, not a strict
upgrade in either direction:

| | **ML-DSA-65** (recommended default) | **FN-DSA-512** |
|---|---|---|
| Public key | 1952 bytes | 897 bytes |
| Signature | ≤3309 bytes | ≤666 bytes |
| WASM-compatible (as a library dependency) | ✅ Yes (pure Rust) | ✅ Yes (pure Rust, via `fn-dsa`) |
| Dependency | Pure Rust (`ml-dsa`) | Pure Rust (`fn-dsa`) |
| Multikey encoding | Officially registered multicodec | Provisional `0x307` private-use code |
| Side-channel history | None known | Falcon's reference floating-point sampling has a documented history of non-constant-time implementations in some revisions (see `SECURITY.md`) |

**Choose FN-DSA when:** signature/key size is the binding constraint (e.g. bandwidth-limited
transport, on-chain storage, high-frequency signing where payload size dominates) and you can
accept the current lack of upstream Multikey standardization (see the provisional-codes
callout above).

**Choose ML-DSA when:** Multikey interop with third-party (non-0x307) multicodec tooling
matters — which is the common case, hence ML-DSA-65 remaining this crate's
[`PRIMARY_ALGORITHM`](src/lib.rs).

## What's new in 0.4.0 — Domain separation & pre-hash

Every algorithm family (ML-DSA, SLH-DSA, and — behind `fndsa` — FN-DSA) now exposes a
`sign_ctx`/`verify_ctx` trio (FIPS 204/205/206 context strings) and a
`sign_prehash`/`verify_prehash` trio (`HashML-DSA`/`HashSLH-DSA` for large payloads),
plus the `hybrid` feature can now bridge an *existing* Ed25519 identity. See
[`docs/SAGP_NOTES.md`](docs/SAGP_NOTES.md) for the SAGP-specific policy this maps onto.

**Domain-separated signing** — bind a signature to a specific purpose
([`examples/domain_separation.rs`](examples/domain_separation.rs)):

```rust,ignore
let sig = keypair.sign_ctx(&mut OsRng, b"8gentz-agent-v1", msg)?;
MlDsa65Keypair::verify_ctx(&pk, b"8gentz-agent-v1", msg, &sig)?;
```

**Pre-hash signing for large payloads** — sign only a digest, never the whole payload
twice ([`examples/prehash_large_payload.rs`](examples/prehash_large_payload.rs)):

```rust,ignore
let digest = Sha512::digest(&module_bytes);
let sig = keypair.sign_prehash_deterministic(b"8gentz-module-v1", PreHash::Sha512, &digest)?;
MlDsa65Keypair::verify_prehash(&pk, b"8gentz-module-v1", PreHash::Sha512, &digest, &sig)?;
```

**Hybrid bridge for an existing classical identity** — wrap an already-deployed Ed25519
key instead of generating a new one
([`examples/hybrid_bridge.rs`](examples/hybrid_bridge.rs)):

```rust,ignore
let signer = HybridSigner::from_ed25519_secret(&mut OsRng, &legacy_ed25519_seed)?;
let sig = signer.sign_ctx(&mut OsRng, b"8gentz-agent-v1", msg)?;
```

## Release

| Version | Date | Artifacts |
|---------|------|-----------|
| **v0.4.0** | 2026-09-09 | [crates.io](https://crates.io/crates/pqc-sig/0.4.0) |
| v0.3.0 | 2026-09-02 | [crates.io](https://crates.io/crates/pqc-sig/0.3.0) |
| v0.2.1 | 2026-09-01 | [crates.io](https://crates.io/crates/pqc-sig/0.2.1) |
| v0.2.0 | 2026-09-01 | [crates.io](https://crates.io/crates/pqc-sig/0.2.0) |
| v0.1.0 | 2026-08-01 | [pqc-sig-v0.1.0-wasm.zip](https://github.com/0x307/pqc-sig/releases/download/v0.1.0/pqc-sig-v0.1.0-wasm.zip) |

## Algorithms

| Algorithm | Standard | Security Level | Public Key | Signature | WASM |
|-----------|----------|---------------|------------|-----------|------|
| **ML-DSA-44** | FIPS 204 | 2 (128-bit) | 1312 B | 2420 B | ✅ |
| **ML-DSA-65** | FIPS 204 | 3 (192-bit) | 1952 B | 3309 B | ✅ |
| **ML-DSA-87** | FIPS 204 | 5 (256-bit) | 2592 B | 4627 B | ✅ |
| SLH-DSA-SHA2-128s | FIPS 205 | 1 | 32 B | 7856 B | ✅ |
| SLH-DSA-SHA2-128f | FIPS 205 | 1 | 32 B | 17088 B | ✅ |
| SLH-DSA-SHA2-192s | FIPS 205 | 3 | 48 B | 16224 B | ✅ |
| SLH-DSA-SHA2-192f | FIPS 205 | 3 | 48 B | 35664 B | ✅ |
| SLH-DSA-SHA2-256s | FIPS 205 | 5 | 64 B | 29792 B | ✅ |
| SLH-DSA-SHA2-256f | FIPS 205 | 5 | 64 B | 49856 B | ✅ |
| SLH-DSA-SHAKE-128s | FIPS 205 | 1 | 32 B | 7856 B | ✅ |
| SLH-DSA-SHAKE-128f | FIPS 205 | 1 | 32 B | 17088 B | ✅ |
| SLH-DSA-SHAKE-192s | FIPS 205 | 3 | 48 B | 16224 B | ✅ |
| SLH-DSA-SHAKE-192f | FIPS 205 | 3 | 48 B | 35664 B | ✅ |
| SLH-DSA-SHAKE-256s | FIPS 205 | 5 | 64 B | 29792 B | ✅ |
| SLH-DSA-SHAKE-256f | FIPS 205 | 5 | 64 B | 49856 B | ✅ |
| FN-DSA-512 (Falcon) | FIPS 206‡ | 1 | 897 B | 666 B | ✅* |
| FN-DSA-1024 (Falcon) | FIPS 206‡ | 5 | 1793 B | 1280 B | ✅* |

*FN-DSA is pure Rust and WASM-compatible. Enable with `--features fndsa`.
‡FIPS 206 (FN-DSA/Falcon) is not yet finalized; it is currently a draft standard pending ratification.

**Recommended:** ML-DSA-65 for general use (best balance of security and performance).

## Build Requirements

- **Rust 1.85 or later** (edition 2021) — this is the crate's declared `rust-version`
  (MSRV), enforced by the `msrv` job in [`ci.yml`](.github/workflows/ci.yml), which builds
  the working tree with a pinned Rust 1.85.0 toolchain on every push/PR. The MSRV is driven
  by a transitive dependency in the default build (a `block-buffer` version pulled in via
  `slh-dsa`'s hashing chain requires the `edition2024` Cargo feature, stabilized in Rust
  1.85.0) — not by this crate's own code. No nightly features are used. The MSRV promise
  covers `cargo build`/`cargo check` only, not `cargo test`: a couple of this crate's
  dev-only interop-test dependencies need a newer toolchain, but dev-dependencies are never
  pulled in by downstream consumers.
- No C compiler, credentials, network services, or local files outside the repo are needed
  to build or test this crate — every optional feature (`fndsa`, `hybrid`) is pure Rust.

## Safety

This crate's own code contains **zero `unsafe`**, enforced by `#![forbid(unsafe_code)]` in
[`src/lib.rs`](src/lib.rs) — this is true of the default build and every combination of this
crate's own features, and there is no C FFI anywhere in the dependency tree (the `fndsa`
feature dropped its C FFI dependency — see [release notes](release-notes.md)). It is **not**
true of the dependency graph as a whole in the stronger sense of "no `unsafe` anywhere": the
optional `fndsa` feature (`fn-dsa`) and `hybrid` feature (`curve25519-dalek`, via
`ed25519-dalek`) both use `unsafe` internally for architecture-specific performance paths
(AVX2 intrinsics, native floating point) — safe Rust, not FFI, and gated behind non-default
features. The default build has zero `unsafe` in its entire dependency tree.

## Continuous Integration

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs on every push and pull request, on
a fresh GitHub-hosted runner with no dependency or build caching — every run is a genuine
clean-room build.

Seven jobs:

- **Default features (build + test)** — `cargo build` / `cargo test` with default features.
  The crate's supported surface; must always pass.
- **`--all-features` (build + test)** — same, with every optional algorithm feature enabled.
- **Packaged artifact (default features)** — builds and tests the actual packaged `.crate`
  output (what `cargo add pqc-sig` ships), not just the working tree — catches
  `.gitignore`/package-`exclude` mistakes that only surface for someone installing the
  published crate.
- **Packaged artifact (`--all-features`)** — same, with every optional feature enabled.
- **MSRV (Rust 1.85.0, build)** — builds (not tests — see
  [Build Requirements](#build-requirements)) against the pinned MSRV toolchain, not `stable`.
  Fails the moment any code or dependency bump relies on a newer language feature than the
  declared `rust-version`.
- **`pqc-sig-wasm` (wasm32 cdylib artifact)** — builds the real standalone WASM artifact,
  `cargo build --target wasm32-unknown-unknown --no-default-features` in `pqc-sig-wasm/`.
  This is the job that would have caught the crate-split defect this repo used to have —
  every other job only ever built the root crate by itself.
- **Downstream consumer (no_std + external std leak, wasm32)** — builds
  [`tests/downstream-consumer-fixture`](tests/downstream-consumer-fixture/), a minimal crate
  depending on `pqc-sig` with `default-features = false` alongside an independent `getrandom`
  dependency that leaks real `std` via `wasm-bindgen` on `wasm32` regardless of `pqc-sig`'s
  own `no_std`-ness. A second build of `pqc-sig` alone proves nothing here — only a
  consumer's build graph exposes this class of regression.

## Dependency scanning

[`.github/workflows/cargo-deny.yml`](.github/workflows/cargo-deny.yml) runs
[`cargo-deny`](https://embarkstudios.github.io/cargo-deny/) against [`deny.toml`](deny.toml)
— advisories, bans, licenses and sources — on every push to `main`, every pull request, and
weekly on Mondays at 06:00 UTC. A failing scheduled run opens or updates a tracking issue
labelled `security` / `cargo-deny`.

It is a **separate workflow from `ci.yml` on purpose**, and it is **not a required status
check** — that stays true even now that the `advisories` check passes cleanly, since a future
advisory landing on any dependency shouldn't block merges by default; it should surface
visibly instead. Any accepted advisory would be listed by RUSTSEC ID in
[`SECURITY.md`](./SECURITY.md#known-and-accepted-advisories) — not hidden with an ignore
list, and not papered over with `continue-on-error`.

## Quick Start

```toml
[dependencies]
pqc-sig = "0.4"
```

```rust,no_run
use pqc_sig::fips204::MlDsa65Keypair;
use rand::rngs::OsRng;

// Generate a keypair
let keypair = MlDsa65Keypair::generate(&mut OsRng).unwrap();
let pk = keypair.public_key();

// Sign a message
let message = b"Hello, post-quantum world!";
let signature = keypair.sign(&mut OsRng, message).unwrap();

// Verify the signature
MlDsa65Keypair::verify(&pk, message, &signature).unwrap();
```

## WASM Usage

`pqc-sig` itself is a pure library (`rlib`-only) and is never built as a standalone WASM
artifact — Cargo builds every declared crate-type for a package regardless of what a
consumer needs, so a `cdylib` declaration here would force the `#[global_allocator]`/
`#[panic_handler]` lang-item question onto every consumer, including ones that already have
their own `std`. The sibling [`pqc-sig-wasm`](pqc-sig-wasm/) crate exists specifically to be
that final artifact.

Build the WASM binary via the sibling crate:

```powershell
powershell -ExecutionPolicy Bypass -File build-wasm.ps1
```

### JavaScript/TypeScript

```javascript
import init, {
  // ML-DSA
  WasmMlDsa44Keypair, WasmMlDsa65Keypair, WasmMlDsa87Keypair,
  ml_dsa_44_verify, ml_dsa_65_verify, ml_dsa_87_verify,
  // SLH-DSA (all 12 variants)
  WasmSlhDsaSha2_128sKeypair, WasmSlhDsaSha2_128fKeypair,
  WasmSlhDsaSha2_192sKeypair, WasmSlhDsaSha2_192fKeypair,
  WasmSlhDsaSha2_256sKeypair, WasmSlhDsaSha2_256fKeypair,
  WasmSlhDsaShake128sKeypair, WasmSlhDsaShake128fKeypair,
  WasmSlhDsaShake192sKeypair, WasmSlhDsaShake192fKeypair,
  WasmSlhDsaShake256sKeypair, WasmSlhDsaShake256fKeypair,
  slh_dsa_sha2_128s_verify, slh_dsa_sha2_128f_verify,
  slh_dsa_sha2_192s_verify, slh_dsa_sha2_192f_verify,
  slh_dsa_sha2_256s_verify, slh_dsa_sha2_256f_verify,
  slh_dsa_shake_128s_verify, slh_dsa_shake_128f_verify,
  slh_dsa_shake_192s_verify, slh_dsa_shake_192f_verify,
  slh_dsa_shake_256s_verify, slh_dsa_shake_256f_verify,
  // Utilities
  pqc_sig_version,
} from './pqc_sig.js';

await init();

// Generate keypair
const keypair = new WasmMlDsa65Keypair();
const pubKeyBytes = keypair.public_key_bytes();

// Sign
const message = new TextEncoder().encode("Hello, post-quantum world!");
const signature = keypair.sign(message);

// Verify
const valid = ml_dsa_65_verify(pubKeyBytes, message, signature);
console.log("Valid:", valid); // true

console.log("Version:", pqc_sig_version()); // e.g. "0.4.0"
```

## Hybrid Signatures

The opt-in `hybrid` feature adds an Ed25519 + ML-DSA-65 combiner for bridging classical
deployments to PQC during migration: `HybridSigner` produces both signatures, and
verification requires both to pass — an attacker must break both primitives to forge one.

```toml
pqc-sig = { version = "0.4", features = ["hybrid"] }
```

```rust,ignore
// Not run as a doctest: this README is included as the crate's top-level doc comment
// (`#![doc = include_str!("../README.md")]`), which compiles unconditionally — the
// `hybrid` feature isn't guaranteed enabled there. See `src/hybrid.rs` for the
// feature-gated, actually-tested version of this example.
use rand::rngs::OsRng;
use pqc_sig::hybrid::HybridSigner;

let signer = HybridSigner::generate(&mut OsRng).unwrap();
let pk = signer.public_key();

let message = b"Hello, hybrid world!";
let signature = signer.sign(message).unwrap();

HybridSigner::verify(message, &signature, &pk).unwrap();
```

## WASM Component Model

The `wit/pqc-sig.wit` file defines the [WIT (WebAssembly Interface Types)](https://component-model.bytecodealliance.org/design/wit.html) interface for this library, enabling use as a WASM Component with any compliant runtime.

**Package:** `x307:pqc-sig@0.4.0`

### WIT Interface Summary

```wit
package x307:pqc-sig@0.4.0;

interface types { ... }      // sig-algorithm enum, sig-error variant
interface ml-dsa { ... }     // ML-DSA-44/65/87 keypair resource + sign/verify
interface slh-dsa { ... }    // SLH-DSA all 12 parameter sets
interface pqc-sig { ... }    // Unified dispatch interface

world pqc-sig-world {
    export ml-dsa;
    export slh-dsa;
    export pqc-sig;
}
```

### Using with wasmtime (CLI)

```bash
# Run a component that imports pqc-sig
wasmtime run --component my-app.wasm
```

### Using with jco (Node.js / Browser)

```bash
# Transpile the component for browser/Node.js use
npx jco transpile pqc_sig_bg.wasm -o dist-jco/

# Then import in your JS/TS project:
import { mlDsa, slhDsa } from './dist-jco/pqc_sig.js';
```

### WIT File Location

The WIT interface is at [`wit/pqc-sig.wit`](wit/pqc-sig.wit) and is also included in the WASM release artifact (`dist/pqc-sig.wit`, produced by [`build.ps1`](build.ps1); historically shipped as `pqc-sig-v0.1.0-wasm.zip` in the v0.1.0 release — see the [Release](#release) table).

## `no_std` Support

This crate is `no_std`-compatible with `alloc`. Disable the `std` feature:

```toml
pqc-sig = { version = "0.4", default-features = false }
```

## Features

| Feature | Description |
|---------|-------------|
| `std` (default) | Enable `std`-dependent trait impls |
| `fndsa` | Enable FN-DSA/Falcon (pure Rust, WASM-compatible) |
| `hybrid` | Enable the Ed25519 + ML-DSA-65 hybrid combiner (pure Rust, WASM-compatible) |

## Algorithm Selection Guide

| Use Case | Recommended Algorithm |
|----------|----------------------|
| General purpose (balanced) | **ML-DSA-65** (FIPS 204) |
| Maximum security | ML-DSA-87 (FIPS 204) |
| Minimum key size | ML-DSA-44 (FIPS 204) |
| WASM module integrity | SLH-DSA-SHA2-128s (FIPS 205) |
| Compact signatures | FN-DSA-512 (FIPS 206) |
| Audit/long-term archival | ML-DSA-87 (FIPS 204) |
| Bridging a classical deployment to PQC | Hybrid Ed25519 + ML-DSA-65 (`hybrid` feature) |

## Security Notes

- **PQC-only by default** — classical cryptography (Ed25519) is opt-in only via the `hybrid` feature, for migration bridging
- **No KEM** — signatures only (see `pqc-kem` for key encapsulation)
- **Caller-provided RNG** — no `OsRng` hardcoding in library code
- **Zeroize on drop** — secret keys are automatically zeroed when dropped
- **All operations return `SigResult<T>`** — never panics

## Architecture

```text
pqc-sig/
├── src/
│   ├── lib.rs          — crate root, re-exports, no_std gate
│   ├── error.rs        — SigError enum, SigResult alias
│   ├── types.rs        — wire types (SigPublicKey, SigSecretKey, Signature, SignedMessage)
│   ├── fips204/        — ML-DSA (FIPS 204): ML-DSA-44/65/87
│   ├── fips205/        — SLH-DSA (FIPS 205): 12 parameter sets
│   ├── fips206/        — FN-DSA (FIPS 206): Falcon-512/1024 (feature = "fndsa")
│   └── hybrid.rs       — Ed25519 + ML-DSA-65 combiner (feature = "hybrid")
├── pqc-sig-wasm/       — sibling crate: the standalone WASM cdylib artifact + JS bindings
├── tests/              — integration tests
│   └── downstream-consumer-fixture/  — regression fixture for the no_std/std-leak defect
└── wit/                — WIT interface for WASM Component Model
```

## Release Notes

### v0.1.0 (2026-08-01) — Initial Release

- **17 algorithms implemented**: ML-DSA-44/65/87, all 12 SLH-DSA variants, FN-DSA-512/1024
- **105 tests passing with `--features fndsa`** (86 without Falcon)
- **WASM-compatible**: ML-DSA (all 3 variants) + SLH-DSA (all 12 variants) compile to `wasm32-unknown-unknown`
- **WIT Component Model interface** at `wit/pqc-sig.wit`
- Standalone crate — no workspace coupling, `no_std` + `alloc`
- Caller-provided RNG, secret keys zeroized on drop

See [release-notes.md](release-notes.md) for full details, and [CHANGELOG.md](CHANGELOG.md)
for the authoritative Keep-a-Changelog-format record.

## Stability and support

This project ships `0.x`. See [`STABILITY.md`](./STABILITY.md) for what counts as a breaking
change, deprecation notice, release cadence, and support posture.

## Security

See [`SECURITY.md`](./SECURITY.md) to report a vulnerability. It also lists any known,
accepted dependency advisories (currently none — see
[`SECURITY.md`](./SECURITY.md#known-and-accepted-advisories)) and the dependency-scanning
setup.

## Contributing

See [`CONTRIBUTING.md`](./CONTRIBUTING.md), including the current external-contribution
posture.

## License

MIT OR Apache-2.0 — see [`LICENSE-MIT`](./LICENSE-MIT) and [`LICENSE-APACHE`](./LICENSE-APACHE).

## Maintainer

Ed Johnson

---

## The 0x307 crate family

`pqc-sig` is one of six open-source crates from [0x307](https://0x307.com/crates), held to one
audit and stability standard.

| Crate | Tier | What it does |
|---|---|---|
| [pqc-sig](https://crates.io/crates/pqc-sig) (this crate) | Production | ML-DSA, SLH-DSA and FN-DSA signatures (FIPS 204/205/206) |
| [pqc-kem](https://crates.io/crates/pqc-kem) | Production | ML-KEM (FIPS 203), the X25519 + ML-KEM-768 hybrid, X-Wing, and sealed boxes |
| [aethel-core](https://crates.io/crates/aethel-core) | Production | Post-quantum anonymous identity: a separate identifier per context, context-bound ML-DSA signing |
| [aethel-sdk](https://crates.io/crates/aethel-sdk) | Preview | The SDK over aethel-core, and the place to start |
| [aethel-vault](https://crates.io/crates/aethel-vault) | Preview | Agent-held wallet: policy-gated x402 / EIP-3009 signing with ML-DSA-65 spend records |
| [pqc-privacy](https://crates.io/crates/pqc-privacy) | Lab | Research bundle, kept off every identity and payment path |

**Production** crates are thin, standards-bound libraries meant to be depended on today. **Preview** crates work and are published, with APIs still settling. **Lab** crates are research, never on an identity or payment path.

**Runnable examples:** [0x307/examples](https://github.com/0x307/examples), one program per
crate, pinned to the published versions.

**Audit status:** None of these crates has been independently audited, and none holds a CMVP / FIPS 140-3 validation. "FIPS 203/204/205/206" means the algorithms follow those standards, not that the code is certified. Known issues for this crate are in
[SECURITY.md](https://github.com/0x307/pqc-sig/blob/main/SECURITY.md). Versioning and yanks:
[STABILITY.md](https://github.com/0x307/pqc-sig/blob/main/STABILITY.md).
