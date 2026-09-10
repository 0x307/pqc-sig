# Multicodec / Multikey Reference

**Scope:** this document is the single, discoverable place that records the
[multiformats/multicodec](https://github.com/multiformats/multicodec) code every
[`SigAlgorithm`](../src/types.rs) variant uses, which of those codes are officially
registered upstream vs. this crate's own provisional reservation, and the exact
Multikey byte layout [`SigPublicKey::to_multibase`](../src/types.rs)/
[`SigPublicKey::from_multibase`](../src/types.rs) produce/consume. It supersedes the
one-paragraph FN-DSA callouts scattered across `README.md`/`docs/SAGP_NOTES.md` as the
canonical reference — those documents link here instead of repeating the table.

## How a `pqc-sig` Multikey is built

A [W3C Multikey](https://www.w3.org/TR/controller-document/#multikey) is:

```text
multibase('z', base58btc( varint(multicodec_code) ‖ raw_public_key_bytes ))
```

`pqc-sig` implements this generically in [`SigPublicKey::to_multibase`]/
[`from_multibase`](../src/types.rs:375) for **all 17** [`SigAlgorithm`] variants: the
multicodec code is looked up via [`SigAlgorithm::multicodec_code`](../src/types.rs:193),
LEB128-varint-encoded ([`encode_varint`](../src/types.rs:289)), prefixed onto the raw
public key bytes, and base58btc-encoded with a leading `z`. Decoding
([`from_multibase`](../src/types.rs:388)) reverses this and additionally checks that the
embedded code matches the `algorithm` the caller expected.

## Code table

| `SigAlgorithm` variant | Multicodec code (hex) | Varint bytes | Status | Source |
|---|---|---|---|---|
| `MlDsa44` | `0x1210` | `90 24` | **registered** (draft) | [multicodec table](https://github.com/multiformats/multicodec/blob/master/table.csv) — `ml-dsa-44` |
| `MlDsa65` | `0x1211` | `91 24` | **registered** (draft) | [multicodec table](https://github.com/multiformats/multicodec/blob/master/table.csv) — `ml-dsa-65` |
| `MlDsa87` | `0x1212` | `92 24` | **registered** (draft) | [multicodec table](https://github.com/multiformats/multicodec/blob/master/table.csv) — `ml-dsa-87` |
| `SlhDsaSha2_128s` | `0x1220` | `A0 24` | **registered** (draft) | [multicodec table](https://github.com/multiformats/multicodec/blob/master/table.csv) — `slh-dsa-sha2-128s` |
| `SlhDsaShake128s` | `0x1221` | `A1 24` | **registered** (draft) | multicodec table — `slh-dsa-shake-128s` |
| `SlhDsaSha2_128f` | `0x1222` | `A2 24` | **registered** (draft) | multicodec table — `slh-dsa-sha2-128f` |
| `SlhDsaShake128f` | `0x1223` | `A3 24` | **registered** (draft) | multicodec table — `slh-dsa-shake-128f` |
| `SlhDsaSha2_192s` | `0x1224` | `A4 24` | **registered** (draft) | multicodec table — `slh-dsa-sha2-192s` |
| `SlhDsaShake192s` | `0x1225` | `A5 24` | **registered** (draft) | multicodec table — `slh-dsa-shake-192s` |
| `SlhDsaSha2_192f` | `0x1226` | `A6 24` | **registered** (draft) | multicodec table — `slh-dsa-sha2-192f` |
| `SlhDsaShake192f` | `0x1227` | `A7 24` | **registered** (draft) | multicodec table — `slh-dsa-shake-192f` |
| `SlhDsaSha2_256s` | `0x1228` | `A8 24` | **registered** (draft) | multicodec table — `slh-dsa-sha2-256s` |
| `SlhDsaShake256s` | `0x1229` | `A9 24` | **registered** (draft) | multicodec table — `slh-dsa-shake-256s` |
| `SlhDsaSha2_256f` | `0x122a` | `AA 24` | **registered** (draft) | multicodec table — `slh-dsa-sha2-256f` |
| `SlhDsaShake256f` | `0x122b` | `AB 24` | **registered** (draft) | multicodec table — `slh-dsa-shake-256f` |
| `FnDsa512` | `0x307000` | `80 E0 C1 01` | **provisional / private-use** | this crate only — [`FN_DSA_PRIVATE_USE_BASE`](../src/types.rs:285) |
| `FnDsa1024` | `0x307001` | `81 E0 C1 01` | **provisional / private-use** | this crate only — [`FN_DSA_PRIVATE_USE_BASE`](../src/types.rs:285) |

Varint bytes were computed by hand per the
[unsigned-varint spec](https://github.com/multiformats/unsigned-varint) (7 bits per byte,
LSB-first, continuation bit set on all but the last byte) and match
[`encode_varint`](../src/types.rs:289)'s output for each code; they are listed for
convenience when inspecting raw Multikey bytes on the wire, not as a separate source of
truth — the code column and [`SigAlgorithm::multicodec_code`](../src/types.rs:193) are
authoritative.

The registered `0x1210`–`0x122b` block (ML-DSA, SLH-DSA) is independently
cross-checked against the `multibase`/`ssi-multicodec` crates in
[`tests/ssi_interop_test.rs`](../tests/ssi_interop_test.rs) — those 15 codes are real,
external, third-party-verifiable multicodec table entries, carrying draft status in the
upstream table (not yet a final/stable multicodec registration, but a real assigned code,
unlike FN-DSA below).

## FN-DSA codes are provisional

`FnDsa512` (`0x307000`) and `FnDsa1024` (`0x307001`) are **not** entries in the upstream
[multiformats/multicodec table](https://github.com/multiformats/multicodec/blob/master/table.csv).
As of this writing there is no registered, pending, or open-PR multicodec code for
FN-DSA/Falcon anywhere in that table. `pqc-sig` self-assigns these two codes from its own
`0x307`-namespaced private-use block (see
[`FN_DSA_PRIVATE_USE_BASE`](../src/types.rs:229) for the full rationale) so that
`to_multibase()`/`from_multibase()` do not have to permanently error for FN-DSA while
waiting on an upstream registration with no committed timeline.

**What this means in practice:**

- **These codes will change.** Once [FIPS 206](https://csrc.nist.gov/pubs/fips/206/ipd)
  is finalized and multiformats/multicodec registers an official FN-DSA/Falcon code,
  `SigAlgorithm::multicodec_code()` will migrate `FnDsa512`/`FnDsa1024` to that code in a
  follow-up **minor** release, per the "Revisit trigger" in
  [`FN_DSA_PRIVATE_USE_BASE`](../src/types.rs:278)'s doc comment. Every FN-DSA Multikey
  persisted before that point will need to be re-encoded.
- **MUST NOT be used as the SAGP default.** [`crate::PRIMARY_ALGORITHM`] is
  `"ML-DSA-65"`, which uses a registered code; nothing in this crate defaults to FN-DSA.
  See `docs/SAGP_NOTES.md`'s "FN-DSA: not for default use" section for the SAGP-specific
  policy statement.
- **Interop scope is 0x307-controlled systems only.** A Multikey carrying `0x307000`/
  `0x307001` is only meaningful between parties that both run `pqc-sig ≥ 0.3` (the first
  published version with these codes) and both recognize this crate's private-use
  reservation. A generic, independent multicodec-table-driven decoder — one that only
  knows the canonical `table.csv` — will not recognize `0x307000`/`0x307001` as FN-DSA at
  all; it will either error or (worse, for a sufficiently permissive decoder) treat the
  bytes as whatever *its own* assignment of that code happens to be, if any. Do not hand
  a `pqc-sig`-produced FN-DSA Multikey to a third-party system unless you have confirmed
  it specifically understands this crate's private-use block.
- **Programmatic check:** call
  [`SigAlgorithm::is_private_use_multicodec()`](../src/types.rs:224) before persisting or
  transmitting a Multikey to decide whether to warn, log, or reject. It returns `true`
  for `FnDsa512`/`FnDsa1024` and `false` for all 15 registered ML-DSA/SLH-DSA variants.

  ```rust
  use pqc_sig::types::SigAlgorithm;

  let alg = SigAlgorithm::FnDsa512;
  if alg.is_private_use_multicodec() {
      // warn / log / reject before handing this Multikey to a third party
  }
  ```

### Tracking

- [ ] **Upstream multicodec PR** — no PR or issue exists yet for FN-DSA/Falcon in
      [multiformats/multicodec](https://github.com/multiformats/multicodec). TODO: file
      one and link it here once opened (`TODO: <PR/issue URL>`).
- [ ] **FIPS 206 final publication** — currently a NIST **draft** (ipd) standard; not
      finalized. Track at <https://csrc.nist.gov/pubs/fips/206/ipd>. An upstream
      multicodec registration is unlikely to land before FIPS 206 is final.
- [ ] **Planned migration** (once an upstream code is registered), in order:
  1. Add the new registered code as the value `SigAlgorithm::multicodec_code()` returns
     for `FnDsa512`/`FnDsa1024`.
  2. Deprecate (but do not immediately remove) recognition of `0x307000`/`0x307001`:
     `from_multibase()` dual-accepts both the new registered code and the old
     `0x307xxx` private-use codes for **one minor version**, so already-persisted
     Multikeys don't break on upgrade.
  3. After that deprecation window, drop the private-use codes from `from_multibase()`
     entirely and update this document accordingly.
  4. Record the migration in `CHANGELOG.md` per `STABILITY.md`'s wire-format-break
     rules, even though the *code itself* is explicitly documented as provisional (the
     wire bytes it produces still change).

---

See also: [`docs/SAGP_NOTES.md`](SAGP_NOTES.md) for how this maps onto SAGP algorithm
selection policy, and [`src/types.rs`](../src/types.rs) for the implementation.
