# pqc-sig

**Post-quantum digital signatures** — a standalone, WASM-compatible Rust library implementing NIST-standardized post-quantum signature algorithms.

[![CI](https://github.com/0x307/pqc-sig/actions/workflows/ci.yml/badge.svg)](https://github.com/0x307/pqc-sig/actions/workflows/ci.yml)
[![cargo-deny](https://github.com/0x307/pqc-sig/actions/workflows/cargo-deny.yml/badge.svg)](https://github.com/0x307/pqc-sig/actions/workflows/cargo-deny.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![FIPS 204](https://img.shields.io/badge/FIPS-204%20ML--DSA-green.svg)](https://csrc.nist.gov/pubs/fips/204/final)
[![FIPS 205](https://img.shields.io/badge/FIPS-205%20SLH--DSA-green.svg)](https://csrc.nist.gov/pubs/fips/205/final)
[![FIPS 206](https://img.shields.io/badge/FIPS-206%20FN--DSA-orange.svg)](https://csrc.nist.gov/pubs/fips/206/ipd)

> **Reading the badges:** **CI** is the build-and-test signal — it should be green, and a red
> one means something is actually broken. **cargo-deny** is the dependency-advisory signal and
> is **expected to be red**: the upstream PQClean project is being archived, so the
> optional `fndsa` feature's dependencies carry unmaintained advisories that are
> [known and accepted](SECURITY.md#known-and-accepted-advisories), not suppressed. A red
> cargo-deny badge is the documented state, not a broken build.

## What runs today vs. what is designed

**Runs today:**

- ML-DSA-44/65/87 (FIPS 204) and all 12 SLH-DSA parameter sets (FIPS 205) — pure Rust,
  `no_std` + `alloc`, directly compilable to `wasm32-unknown-unknown`, keygen/sign/verify
  covered by integration tests (86 tests passing by default; 105 with `--features fndsa`).
- **FN-DSA-512/1024 (Falcon, FIPS 206 draft)** via C FFI (`pqcrypto-falcon`), gated behind the
  `fndsa` feature flag — **production-usable today, not provisional**: a real, working,
  tested implementation. Requires a C compiler. **Not WASM-compatible**; use ML-DSA or
  SLH-DSA for WASM targets. `fndsa` stays non-default because this crate's primary posture
  is WASM-first, not because FN-DSA itself is unfinished. See "When to choose FN-DSA over
  ML-DSA" below for guidance on when its smaller keys/signatures are worth the C-FFI
  tradeoff.
- `SigPublicKey::to_multibase()` / `from_multibase()` — W3C Multikey encoding for **all 17**
  algorithms, including FN-DSA. ML-DSA/SLH-DSA use officially registered (draft-status)
  multicodec codes, independently verified against the `multibase` and `ssi-multicodec`
  crates (see [`tests/ssi_interop_test.rs`](tests/ssi_interop_test.rs)). **FN-DSA uses a
  provisional, `0x307`-reserved private-use multicodec code** (`0x307000`/`0x307001`) instead
  — see [`src/types.rs`](src/types.rs)'s `FN_DSA_PRIVATE_USE_BASE` doc comment for the full
  rationale and interop scope (0x307-controlled systems, not generic third-party multicodec
  decoders, until/unless upstream registers a real code).
- WASM bindings (`wasm` feature, `wasm-bindgen`) for ML-DSA and SLH-DSA — see
  [`src/wasm.rs`](src/wasm.rs). FN-DSA has no WASM bindings (it can't compile to `wasm32`).
- A WIT Component Model interface at [`wit/pqc-sig.wit`](wit/pqc-sig.wit) describing the
  ML-DSA and SLH-DSA interfaces for non-Rust WASM runtimes.
- CI (`.github/workflows/ci.yml`) builds and tests both default features and `--all-features`
  on every push/PR, including against the packaged `cargo package` artifact.

**Designed, not yet implemented / provisional:**

- FN-DSA Multikey support uses this crate's own **provisional** private-use multicodec
  codes, not an upstream-registered one — no PR/issue exists yet for FIPS 206/Falcon at
  multiformats/multicodec, and getting one merged is outside 0x307's unilateral control.
  Tracked as a revisit trigger in `FN_DSA_PRIVATE_USE_BASE`'s doc comment; migrating to a
  real code (if/when registered) is a follow-up minor release, not a rewrite.
- FIPS 206 itself is a NIST **draft** standard, not yet finalized (see the FN-DSA badge above)
  — the implementation tracks the draft and may need breaking changes once it's finalized.
- MSRV, `unsafe` code policy, and docs.rs metadata are now stated below (see
  [Build Requirements](#build-requirements) and [Safety](#safety)).

## When to choose FN-DSA over ML-DSA

Both are NIST post-quantum signature standards; the choice is a tradeoff, not a strict
upgrade in either direction:

| | **ML-DSA-65** (recommended default) | **FN-DSA-512** |
|---|---|---|
| Public key | 1952 bytes | 897 bytes |
| Signature | ≤3309 bytes | ≤666 bytes |
| WASM-compatible | ✅ Yes (pure Rust) | ❌ No (C FFI via `pqcrypto-falcon`) |
| Dependency | Pure Rust (`ml-dsa`) | C FFI (`pqcrypto-falcon`) |
| Multikey encoding | Officially registered multicodec | Provisional `0x307` private-use code |
| Side-channel history | None known | Falcon's reference floating-point sampling has a documented history of non-constant-time implementations in some revisions (see `SECURITY.md`) |

**Choose FN-DSA when:** signature/key size is the binding constraint (e.g. bandwidth-limited
transport, on-chain storage, high-frequency signing where payload size dominates), the
signing/verifying context is **native only** (never inside a `wasm32-wasip1` guest — this
matters for SAGP's WASM-guest architecture specifically), and you can accept a C-FFI
dependency plus the current lack of upstream Multikey standardization.

**Choose ML-DSA when:** you need WASM compatibility, you want to stay on the pure-Rust /
zero-FFI default build, or Multikey interop with third-party (non-0x307) multicodec tooling
matters — which is the common case, hence ML-DSA-65 remaining this crate's
[`PRIMARY_ALGORITHM`](src/lib.rs).

## Release

| Version | Date | Artifacts |
|---------|------|-----------|
| **v0.1.0** | 2026-08-01 | [pqc-sig-v0.1.0-wasm.zip](https://github.com/0x307/pqc-sig/releases/download/v0.1.0/pqc-sig-v0.1.0-wasm.zip) |

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
| FN-DSA-512 (Falcon) | FIPS 206‡ | 1 | 897 B | ≤666 B | ❌* |
| FN-DSA-1024 (Falcon) | FIPS 206‡ | 5 | 1793 B | ≤1280 B | ❌* |

*FN-DSA uses C FFI and is not WASM-compatible. Enable with `--features fndsa`.
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
- **A C compiler** (`cc`, e.g. `gcc`/`clang` on Linux/macOS, MSVC on Windows) —
  only needed to build the `fndsa` feature (FN-DSA/Falcon, via `pqcrypto-falcon`'s
  C FFI). Not required for the default build. GitHub's `ubuntu-latest` runners
  ship one out of the box.
- No credentials, network services, or local files outside the repo are needed
  to build or test this crate.

## Safety

This crate's own code contains **zero `unsafe`**, enforced by `#![forbid(unsafe_code)]` in
[`src/lib.rs`](src/lib.rs) — this is true of the default build and every combination of this
crate's own features. It is **not** true of the dependency graph as a whole: the optional
`fndsa` feature pulls in `pqcrypto-falcon`, a real C FFI implementation, so enabling `fndsa`
does bring `unsafe`/FFI code into the build (in that dependency, not in this crate). The
default build (`fndsa` disabled) has no FFI anywhere in its dependency tree.

## Continuous Integration

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs on every push and pull request, on
a fresh GitHub-hosted runner with no dependency or build caching — every run is a genuine
clean-room build.

Five jobs:

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

## Dependency scanning

[`.github/workflows/cargo-deny.yml`](.github/workflows/cargo-deny.yml) runs
[`cargo-deny`](https://embarkstudios.github.io/cargo-deny/) against [`deny.toml`](deny.toml)
— advisories, bans, licenses and sources — on every push to `main`, every pull request, and
weekly on Mondays at 06:00 UTC. A failing scheduled run opens or updates a tracking issue
labelled `security` / `cargo-deny`.

It is a **separate workflow from `ci.yml` on purpose**, and it is **not a required status
check**. The `advisories` check is expected to fail: the optional `fndsa` feature pulls in
`pqcrypto-*` crates whose upstream (PQClean) is being archived. Those advisories are
accepted and listed by RUSTSEC ID in
[`SECURITY.md`](./SECURITY.md#known-and-accepted-advisories) — not hidden with an ignore
list, and not papered over with `continue-on-error`. Keeping the two workflows apart means
the CI badge above stays a truthful build signal while the advisory signal stays visible on
its own.

## Quick Start

```toml
[dependencies]
pqc-sig = "0.1"
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

Build with the `wasm` feature for `wasm32-unknown-unknown` targets:

```toml
pqc-sig = { version = "0.1", default-features = false, features = ["wasm"] }
```

Or build the WASM binary directly:

```powershell
powershell -ExecutionPolicy Bypass -File pqc-sig/build.ps1
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

console.log("Version:", pqc_sig_version()); // "0.1.0"
```

## WASM Component Model

The `wit/pqc-sig.wit` file defines the [WIT (WebAssembly Interface Types)](https://component-model.bytecodealliance.org/design/wit.html) interface for this library, enabling use as a WASM Component with any compliant runtime.

**Package:** `x307:pqc-sig@0.1.0`

### WIT Interface Summary

```wit
package x307:pqc-sig@0.1.0;

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

The WIT interface is at [`wit/pqc-sig.wit`](wit/pqc-sig.wit) and is also included in the WASM release artifact (`pqc-sig-v0.1.0-wasm.zip`).

## `no_std` Support

This crate is `no_std`-compatible with `alloc`. Disable the `std` feature:

```toml
pqc-sig = { version = "0.1", default-features = false }
```

## Features

| Feature | Description |
|---------|-------------|
| `std` (default) | Enable `std`-dependent trait impls |
| `wasm` | Enable `wasm-bindgen` exports + JS entropy |
| `fndsa` | Enable FN-DSA/Falcon via C FFI (NOT WASM-compatible) |

## Algorithm Selection Guide

| Use Case | Recommended Algorithm |
|----------|----------------------|
| General purpose (balanced) | **ML-DSA-65** (FIPS 204) |
| Maximum security | ML-DSA-87 (FIPS 204) |
| Minimum key size | ML-DSA-44 (FIPS 204) |
| WASM module integrity | SLH-DSA-SHA2-128s (FIPS 205) |
| Compact signatures (non-WASM) | FN-DSA-512 (FIPS 206) |
| Audit/long-term archival | ML-DSA-87 (FIPS 204) |

## Security Notes

- **No classical cryptography** — this crate implements PQC-only algorithms
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
│   ├── wasm.rs         — wasm-bindgen exports (feature = "wasm")
│   ├── fips204/        — ML-DSA (FIPS 204): ML-DSA-44/65/87
│   ├── fips205/        — SLH-DSA (FIPS 205): 12 parameter sets
│   └── fips206/        — FN-DSA (FIPS 206): Falcon-512/1024 (feature = "fndsa")
├── tests/              — integration tests
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

See [`SECURITY.md`](./SECURITY.md) to report a vulnerability.
It also lists the known, accepted dependency advisories
([RUSTSEC-2026-0162/0163/0165](./SECURITY.md#known-and-accepted-advisories), all behind the
non-default `fndsa` feature) and the dependency-scanning setup.

## Contributing

See [`CONTRIBUTING.md`](./CONTRIBUTING.md), including the current external-contribution
posture.

## License

MIT OR Apache-2.0 — see [`LICENSE-MIT`](./LICENSE-MIT) and [`LICENSE-APACHE`](./LICENSE-APACHE).

## Maintainer

Ed Johnson
