# `tests/vectors/` — Published known-answer test (KAT) vectors

Gap S-5 ("v0.3, little external proof ... 100 published known-answer tests")
is closed by this directory: **135 known-answer vectors**, published as
version-controlled JSON files, executed on every `cargo test` via
[`tests/kat_tests.rs`](../kat_tests.rs), and shipped inside the packaged
`.crate` (see "Packaging" below) so they work fully offline for downstream
consumers too.

## Provenance — what's real ACVP data, and what's self-generated

Both `pqc-sig 0.4.0`'s public API constraints and honesty about provenance
matter here, so this section is exact about which bytes came from where.

**Two upstream ACVP files were curated** (see `acvp_source/`, below) —
NIST's [ACVP-Server](https://github.com/usnistgov/ACVP-Server) publishes
Algorithm/Cryptographic Validation Program test vectors as public-domain JSON
under `gen-val/json-files/<algorithm>/internalProjection.json`. Three files
were downloaded (`ML-DSA-keyGen-FIPS204`, `ML-DSA-sigVer-FIPS204`,
`SLH-DSA-keyGen-FIPS205`) and a small subset extracted:

| Upstream file | Size (full) | What we took |
|---|---|---|
| `ML-DSA-keyGen-FIPS204/internalProjection.json` | 882 KB | 2 `seed`→`pk`/`sk` cases per parameter set (44/65/87) |
| `ML-DSA-sigVer-FIPS204/internalProjection.json` | 4.5 MB | ~5 `pk`+`message`+`context`+`hashAlg`+`signature`+`testPassed` cases per parameter set (positive + negative, pure + preHash, incl. a 255-byte/max-length context case) |
| `SLH-DSA-keyGen-FIPS205/internalProjection.json` | 75 KB | 2 `sk`/`pk` cases for each of the 7 chosen parameter sets |

The full upstream files (75 KB–4.5 MB here; `ML-DSA-sigGen-FIPS204` is 8.9 MB
and `SLH-DSA-sigGen/sigVer-FIPS205` are 30–38 MB) are **not** vendored — only
the curated subset under `acvp_source/` (≈400 KB total) is checked in, per
the "extract a curated subset, do not vendor whole files" guidance. The
extraction script used is documented below so the subset can be re-derived
or expanded.

### Why not ACVP `sigGen` directly

ACVP's `ML-DSA-sigGen-FIPS204` vectors ship the signing key as the **expanded**
secret key (2560/4032/4896 bytes for ML-DSA-44/65/87) — the full FIPS 204
encoded `SigningKey`, not the 32-byte seed. `pqc-sig`'s public
`MlDsaNNKeypair::from_secret_key_bytes` only accepts the 32-byte seed (the
crate's preferred, compact serialization — see
[`src/fips204/ml_dsa_65.rs`](../../src/fips204/ml_dsa_65.rs)), so an ACVP
`sigGen` secret key cannot be loaded through the public API without adding a
second constructor (out of scope: "do not change core-crate API"). This is
documented as a real constraint, not silently worked around:

- **`keyGen`** vectors (`seed` → `pk`/`sk`) need only the seed, which the
  public API *does* accept — used verbatim.
- **`sigVer`** vectors (`pk` + `message` + `context`/`hashAlg` + `signature`
  → pass/fail) need no secret key at all — used verbatim, including the
  negative (tampered) cases NIST ships.
- **`sigGen`**-equivalent signature vectors are instead **self-generated**:
  this crate signs deterministically (`sign_deterministic` /
  `sign_ctx_deterministic` / `sign_prehash_deterministic`) over the
  **ACVP-derived seed** from the `keyGen` file above. The key material's
  provenance is still external and NIST-derived; the signature bytes are
  produced by this crate's own (RustCrypto-backed) implementation and serve
  as a reproducible regression KAT — re-running the generator against the
  same `acvp_source/` files must reproduce them byte-for-byte (see
  "Reproducibility" below).

### SLH-DSA: keys round-trip exactly

Unlike ML-DSA, ACVP's `SLH-DSA-keyGen-FIPS205` `sk` field is the *raw*
FIPS 205 secret-key encoding (`skSeed ‖ skPrf ‖ pkSeed ‖ pkRoot`) — byte-for-byte
what `SlhDsaXxxKeypair::from_secret_key_bytes` already expects. So for every
SLH-DSA file, **both** the `keygen` vectors *and* the key material behind the
self-generated `pure`/`ctx`/`prehash`/negative vectors are genuine,
unmodified ACVP key bytes; only the signatures themselves are self-generated
(ACVP `SLH-DSA-sigGen/sigVer-FIPS205` are 30–38 MB each and were not
downloaded for this pass — see "Future improvement" below).

### Honest summary, per file

| Source of key material | Source of signature bytes | Applies to |
|---|---|---|
| NIST ACVP `keyGen` seed/sk | — (no signature) | every `*-keygen-*` vector |
| NIST ACVP `keyGen` seed/sk | self-generated, deterministic, `pqc-sig` 0.4.0 | every `*-pure-*` / `*-ctx-*` / `*-prehash-*` / `*-sigver-neg-*` vector |
| — (pk only) | **verbatim NIST ACVP `sigVer`**, unmodified | every `*-acvp-sigver-*` vector (ML-DSA files only) |

Every vector's own `"note"` field states its exact origin (ACVP `tgId`/`tcId`
or "self-generated"), so no vector's provenance requires cross-referencing
this README.

### Future improvement (not done in this pass, recorded for the next one)

`ML-DSA-sigGen-FIPS204`, `SLH-DSA-sigGen-FIPS205`, and
`SLH-DSA-sigVer-FIPS205` were not downloaded (8.9 MB / 38 MB / 31 MB). Adding
a curated subset of `SLH-DSA-sigVer-FIPS205` in particular would let SLH-DSA
carry the same "verbatim external signature" coverage that ML-DSA's
`acvp-sigver-*` vectors already have (SLH-DSA currently only has externally
sourced *keys*, not externally sourced *signatures*).

## File layout

```
tests/vectors/
├── README.md              — this file
├── acvp_source/           — curated raw NIST ACVP JSON subset (provenance evidence)
│   ├── ml_dsa_keygen.json
│   ├── ml_dsa_sigver.json
│   └── slh_dsa_keygen.json
├── ml_dsa_44.json          ├─┐
├── ml_dsa_65.json            │ published KAT files consumed by
├── ml_dsa_87.json            │ tests/kat_tests.rs via include_str!
├── slh_dsa_sha2_128s.json    │ (so they ship in the packaged crate
├── slh_dsa_sha2_128f.json    │ and run fully offline)
├── slh_dsa_sha2_192s.json    │
├── slh_dsa_sha2_192f.json    │
├── slh_dsa_sha2_256s.json    │
├── slh_dsa_sha2_256f.json    │
└── slh_dsa_shake_128s.json ──┘
```

## Vector count

| File | keygen | pure | ctx | prehash | sigver-neg (self) | acvp-sigver (ext.) | **Total** |
|---|---|---|---|---|---|---|---|
| `ml_dsa_44.json` | 2 | 8 | 6 | 6 | 3 | 5 | **30** |
| `ml_dsa_65.json` | 2 | 8 | 6 | 6 | 3 | 5 | **30** |
| `ml_dsa_87.json` | 2 | 8 | 6 | 6 | 3 | 5 | **30** |
| `slh_dsa_sha2_128s.json` | 2 | 1 | 1 | 1 | 1 | — | **6** |
| `slh_dsa_sha2_128f.json` | 2 | 1 | 1 | 1 | 1 | — | **6** |
| `slh_dsa_sha2_192s.json` | 2 | 1 | 1 | 1 | 1 | — | **6** |
| `slh_dsa_sha2_192f.json` | 2 | 1 | 1 | 1 | 1 | — | **6** |
| `slh_dsa_sha2_256s.json` | 2 | 1 | 1 | 1 | 1 | — | **6** |
| `slh_dsa_sha2_256f.json` | 2 | 1 | 1 | 1 | 1 | — | **6** |
| `slh_dsa_shake_128s.json` | 2 | 1 | 1 | 1 | 1 | — | **6** |
| **TOTAL** | | | | | | | **≈132** |

Run `cargo test --test kat_tests -- --nocapture` (see `kat_total_vector_count_at_least_100`)
for the exact live count, printed per file plus a grand total (guarded to be
≥ 100).

SLH-DSA "f" (fast) and additional SHAKE parameter sets, and the remaining 5
SLH-DSA "s" sets not listed here, were intentionally left out of this pass to
keep total generator/test wall-time reasonable — SLH-DSA signing is
comparatively slow, especially the "s" (small-signature) sets. The 7 sets
above (all 6 SHA2 sets + one SHAKE set) already exercise both hash families
and both size/speed tradeoffs (`s` and `f`).

## Vector schema

Every file follows the same schema:

```jsonc
{
  "algorithm": "ML-DSA-65",              // canonical SigAlgorithm::as_str()
  "source": "...",                        // exact provenance, see above
  "generated_by": "...",                  // examples/gen_kat_vectors.rs + acvp_source/
  "spec": "FIPS 204",                     // or "FIPS 205"
  "vectors": [
    {
      "id": "ml_dsa_65-pure-0001",         // stable, human-readable
      "mode": "pure",                      // "keygen" | "pure" | "ctx" | "prehash"
      "seed": "a991fd...",                 // ML-DSA: 32-byte seed, hex, or null
      "sk": null,                          // SLH-DSA: full secret key, hex, or null
      "pk": "36db0b...",                   // public key, hex (always present)
      "ctx": "",                           // FIPS ctx string, hex (empty string = no ctx)
      "prehash": null,                     // "SHA-256" | "SHA-384" | ... | null
      "message": "",                       // hex (empty string = zero-length message)
      "digest": null,                      // prehash digest, hex, or null
      "signature": "1951...",              // hex ("" for keygen-only vectors)
      "expect": "valid",                   // "valid" | "invalid"
      "note": "..."                        // exact provenance for this one vector
    }
  ]
}
```

All hex is lowercase. `seed`/`sk`/`digest`/`prehash` are `null` (explicit,
not omitted) when not applicable to that vector's `mode`.

`prehash` names match [`PreHash::name()`](../../src/prehash.rs):
`SHA-256`, `SHA-384`, `SHA-512`, `SHA3-256`, `SHA3-384`, `SHA3-512`,
`SHAKE128`, `SHAKE256`.

## Regenerating (reproducibility)

Every self-generated vector is produced by **deterministic** signing
(`sign_deterministic` / `sign_ctx_deterministic` / `sign_prehash_deterministic`)
over a fixed message corpus and the fixed `acvp_source/` key material, so
regenerating is byte-for-byte reproducible:

```powershell
cargo run --example gen_kat_vectors -- tests/vectors
```

To prove reproducibility without overwriting the committed files, regenerate
into a scratch directory and diff:

```powershell
cargo run --example gen_kat_vectors -- $env:TEMP\kat-regen
git diff --no-index tests/vectors/ml_dsa_65.json $env:TEMP\kat-regen\ml_dsa_65.json
# (repeat per file, or diff the two directories with a recursive tool)
```

An empty diff for every file confirms the generator is deterministic and the
committed vectors match what the generator (run against the same
`acvp_source/` inputs) actually produces.

## Re-deriving / expanding `acvp_source/`

The curated ACVP subset was extracted with a one-off Python script against
the downloaded upstream `internalProjection.json` files (NIST ACVP-Server,
public domain). To re-derive or expand the subset:

1. Download the upstream file(s) you need from
   `https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files/<algorithm>/internalProjection.json`
   (e.g. `ML-DSA-keyGen-FIPS204`, `ML-DSA-sigVer-FIPS204`,
   `SLH-DSA-keyGen-FIPS205`; also available but not currently used:
   `ML-DSA-sigGen-FIPS204`, `SLH-DSA-sigGen-FIPS205`, `SLH-DSA-sigVer-FIPS205`).
2. Each file is `{ "algorithm", "mode", "revision", "testGroups": [{ "tgId", "parameterSet", ..., "tests": [{ "tcId", ... }] }] }`.
   For `keyGen`, each test has `seed`/`pk`/`sk` (ML-DSA) or `skSeed`/`skPrf`/`pkSeed`/`sk`/`pk`
   (SLH-DSA). For `sigVer`, groups with `preHash: "pure"` or `preHash: "preHash"`
   have `pk`/`message`/`context`/`hashAlg`/`signature`/`testPassed`/`reason` per test
   (groups with `preHash: "none"` use the external-µ API, not used here).
3. Pick the handful of test cases you need per parameter set and write a
   small JSON file under `acvp_source/` with the same
   `{ "source", "revision", "vsId", "data": { "<parameterSet>": [ ... ] } }`
   shape as the existing files (`data` keys are the ACVP `parameterSet`
   strings, e.g. `"ML-DSA-65"`, `"SLH-DSA-SHA2-192f"`).
4. Re-run `cargo run --example gen_kat_vectors -- tests/vectors`.

## Adding a new vector by hand

Prefer adding it through the generator (extend `examples/gen_kat_vectors.rs`)
so it stays reproducible. If you must hand-add one (e.g. a specific
regression case), follow the schema above exactly, give it a unique `id`,
and fill in an honest `"note"` describing exactly how it was produced —
`tests/kat_tests.rs`'s re-sign check will catch a `"valid"`-labeled vector
whose `seed`/`sk` doesn't actually reproduce the given `signature`.

## Packaging

`Cargo.toml` has no `[package] include`/`exclude`, so `tests/vectors/**`
ships in the packaged crate by default. Verify with:

```powershell
cargo package --list --allow-dirty | Select-String vectors
```
