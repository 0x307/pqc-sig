# SAGP Notes — `pqc-sig` Guidance for the SAGP Ecosystem

**Scope:** this document is a link/summary layer between `pqc-sig`'s crypto primitives and
the SAGP (`8gentz`) specification. The SAGP spec itself is authoritative and lives outside
this repository — treat everything below as *how `pqc-sig` maps onto SAGP*, not as a
replacement for the spec.

---

## Purpose

SAGP agents, modules, and fabric transport need signatures that are:

- **Domain-separated** — a signature made for one purpose (an agent's identity, a fabric
  gossip message, a module's integrity hash) must never be replayable as valid for another
  purpose, even under the same key.
- **Migratable** — agents with an existing classical (Ed25519) identity need a path onto
  post-quantum signatures without discarding that identity outright.
- **Efficient for large payloads** — module bytes and log bundles can be multi-MB; signing
  should not require holding two copies of the payload in memory.

This document records how `pqc-sig`'s `sign_ctx`/`verify_ctx` (see [`crate::MAX_CONTEXT_LEN`]),
`sign_prehash`/`verify_prehash` (see [`crate::prehash::PreHash`]), and hybrid bridge
(see [`crate::hybrid::HybridSigner`]) map onto those three needs.

## Default algorithm: ML-DSA-65

`pqc-sig`'s [`crate::PRIMARY_ALGORITHM`] constant is `"ML-DSA-65"` (NIST FIPS 204, Security
Level 3). **ML-DSA-65 is the default/PRIMARY algorithm for request
signatures.** Concretely:

- Agent identity/spend signatures and module/request signing SHOULD use
  [`crate::fips204::MlDsa65Keypair`] unless a specific role constant
  ([`crate::AUDIT_ALGORITHM`], [`crate::WASM_INTEGRITY_ALGORITHM`],
  [`crate::COMPACT_ALGORITHM`]) says otherwise for that role.
- Hybrid signers (see "Wave 1" below) pair ML-DSA-65 with a classical Ed25519 half;
  `ed25519+ml_dsa_65` is the *only* hybrid combination this crate ships
  ([`crate::hybrid::HYBRID_ALGORITHM`]).

## Domain separation contexts

Every `sign_ctx`/`verify_ctx` call takes a `ctx` byte string (≤ 255 bytes, see
[`crate::MAX_CONTEXT_LEN`]) that structurally separates signatures made for different
purposes — a signature made under one `ctx` will not verify under another, even for the
same key and message. SAGP reserves the following purpose strings:

| Context string | Purpose |
|-----------------|---------|
| `8gentz-agent-v1` | Agent identity and spend-authorization signatures. |
| `8gentz-fabric-v1` | Fabric gossip / transport-layer signatures. |
| `8gentz-module-v1` | Module bytes integrity, signed via [`crate::fips204::MlDsa65Keypair::sign_prehash`] over a digest of the module. |

**Rule: never reuse a context string across purposes.** A key used to sign under
`8gentz-agent-v1` must not also sign under `8gentz-fabric-v1` with the same context value —
each context string is a distinct signing domain, and mixing purposes under one `ctx`
value defeats the separation the mechanism provides. See `examples/domain_separation.rs`
and `examples/hybrid_bridge.rs` for runnable demonstrations of the cross-context rejection.

## Wave 1: accept hybrid Ed25519+ML-DSA-65

`pqc-sig`'s hybrid combiner ([`crate::hybrid::HybridSigner`], feature `hybrid`, **off by
default** — enabling it is an explicit opt-in) is a migration bridge, not a long-term
default:

- **Wave 1 verifiers SHOULD accept `ed25519+ml_dsa_65` hybrid signatures alongside pure
  ML-DSA-65 signatures.** An agent presenting a hybrid signature during Wave 1 is not an
  error condition; both halves passing (see [`crate::hybrid::HybridSigner::verify`]/
  [`crate::hybrid::HybridSigner::verify_ctx`]) is sufficient.
- Signers migrating from a pre-existing classical (Ed25519) identity use
  [`crate::hybrid::HybridSigner::from_ed25519_secret`] to wrap that identity rather than
  discarding it — see `examples/hybrid_bridge.rs`.
- Hybrid is **not** the SAGP default and is not expected to become one; pure ML-DSA-65
  remains [`crate::PRIMARY_ALGORITHM`].
- **Wave 2 (dropping the classical half) and its sunset date are a policy decision left
  as a TODO for the SAGP spec owner.** This document does not set that date; it only
  states that Wave 1 verifiers accept hybrid signatures as a transitional posture.

## Pre-hash for large payloads

Module bytes and other large payloads should be signed via
[`crate::fips204::MlDsa65Keypair::sign_prehash`]/`sign_prehash_deterministic` with
[`crate::prehash::PreHash::Sha512`], under the `8gentz-module-v1` context. This is the
literal FIPS 204 §5.4 `HashML-DSA` construction (see the crate-level "Pre-hash signing"
docs in `src/lib.rs`), not a "sign the digest bytes" shortcut — it is byte-for-byte
interoperable with any other conformant `HashML-DSA` verifier.

**SHA-256 is rejected for ML-DSA-65 (and ML-DSA-87)** — its 128-bit collision strength is
below ML-DSA-65's 192-bit [`crate::fips204::MlDsa65Keypair::SECURITY_STRENGTH_BITS`]
requirement, and the crate returns [`crate::SigError::PreHashTooWeak`] rather than
silently accepting a weaker digest. Use SHA-512 or SHAKE256 for module integrity.

## FN-DSA: not for default use

FN-DSA (NIST FIPS 206 / Falcon, `fndsa` feature) is compact but its Multikey/DID Document
multicodec codes are **provisional, `0x307`-reserved private-use codes** — no upstream
multiformats/multicodec registration exists yet (see
[`crate::types::FN_DSA_PRIVATE_USE_BASE`]). See
[`docs/MULTICODEC.md`](MULTICODEC.md) for the full code table (registered vs. provisional
status for all 17 algorithms), the FN-DSA-specific rationale, interop-scope caveats, and
the upstream-registration/migration tracking checklist.

FN-DSA MUST NOT be the SAGP default signature algorithm; it remains an opt-in role label
([`crate::COMPACT_ALGORITHM`]) for contexts that specifically need the smallest signature
size and can tolerate the provisional-multicodec caveat. [`crate::PRIMARY_ALGORITHM`]
(`"ML-DSA-65"`) is the only algorithm this crate designates as a default, and it uses a
registered multicodec code — never FN-DSA's provisional one.

**Programmatic guard:** any code that selects a default signature algorithm for SAGP
purposes SHOULD assert
[`SigAlgorithm::is_private_use_multicodec()`](../src/types.rs:224) is `false` for whatever
algorithm it is about to install as that default, and reject the choice (or at minimum
warn loudly) if it returns `true`:

```rust
use pqc_sig::types::SigAlgorithm;

fn assert_not_default(alg: SigAlgorithm) {
    assert!(
        !alg.is_private_use_multicodec(),
        "refusing to use a provisional-multicodec algorithm ({alg:?}) as a SAGP default"
    );
}
```

This turns "FN-DSA is never the default" from a documentation-only promise into a check
any SAGP component can run against whatever `SigAlgorithm` its configuration resolves to.
