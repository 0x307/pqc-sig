# Security Policy

## Reporting a vulnerability

Email **security@0x307.com**. This address is monitored and routes to a human — not a
mailing list nobody reads.

Please do not open a public GitHub issue for a suspected vulnerability. Include as much
detail as you can: affected version, reproduction steps, and impact if known.

## Response window

Reports are acknowledged within **5 business days**. This is a best-effort
project with a single maintainer and no on-call rotation — see
[`STABILITY.md`](./STABILITY.md) for the full support posture. The response window above is
the one committed number in that posture; everything else is best-effort.

## Supported versions

This project ships `0.x`. Security fixes land on the latest published minor version. Older
`0.x` minors are not backported to, consistent with the stated stability policy.

## Dependency scanning

[`.github/workflows/cargo-deny.yml`](.github/workflows/cargo-deny.yml) runs
[`cargo-deny`](https://embarkstudios.github.io/cargo-deny/) against
[`deny.toml`](deny.toml) on every push to `main`, on every pull request, and on a weekly
schedule (Mondays 06:00 UTC). A failing scheduled run opens — or comments on — a tracking
issue labelled `security` / `cargo-deny`, so a new advisory surfaces without anyone
remembering to look.

`deny.toml` scans with `all-features = true` deliberately: it covers the full opt-in
surface, including feature-gated algorithms, so anyone who *does* enable a gated feature
already has its advisories on record rather than discovering them afterwards.

`Cargo.lock` is not committed (this is a library), so each run resolves dependencies fresh
against the latest semver-compatible versions — a newly yanked or newly flagged release
gets caught on the next run rather than being pinned out of sight.

### Known and accepted advisories

**The `advisories` check currently fails, and that is the expected, accepted state — not a
broken build.** The advisories below are real and correct; they are accepted and documented
here rather than silenced. `advisories.ignore` in `deny.toml` is deliberately empty: nothing
is suppressed, so a *new* advisory landing on top of these still changes the output.

The upstream [PQClean](https://github.com/PQClean/PQClean) project — which provides the C
implementations behind the `pqcrypto-*` crate family — [is being archived in or after July
2026](https://github.com/PQClean/PQClean/issues/604). Every `pqcrypto-*` crate inherits an
unmaintained advisory as a result.

| Advisory | Crate | How it enters the build |
|---|---|---|
| [RUSTSEC-2026-0165](https://rustsec.org/advisories/RUSTSEC-2026-0165) | `pqcrypto-falcon` | `fndsa` feature (FN-DSA/Falcon) |
| [RUSTSEC-2026-0163](https://rustsec.org/advisories/RUSTSEC-2026-0163) | `pqcrypto-internals` | via `pqcrypto-falcon`, same feature |
| [RUSTSEC-2026-0162](https://rustsec.org/advisories/RUSTSEC-2026-0162) | `pqcrypto-traits` | via `pqcrypto-falcon`, same feature |

**All three are behind the non-default `fndsa` feature.** This crate's `default = ["std"]`;
a default `cargo build` or `cargo test` never links any of them. They appear in the scan
only because `deny.toml` sets `all-features = true`. None is a known vulnerability — each is
an "unmaintained upstream" advisory.

**Why accepted rather than fixed:** the advisories reach a consumer only if that consumer
explicitly opts into `fndsa`, which is exactly the point of gating it — the risk is visible
at the moment you turn the feature on. There is no safe upgrade available; the fix is a
migration, not a version bump.

**Revisit trigger:** migrate the `fndsa` feature to [`fn-dsa`](https://crates.io/crates/fn-dsa)
(pure Rust, actively maintained, WASM-capable). Independently of the advisory, the current
`pqcrypto-falcon` binding is C FFI and **not WASM-compatible**, which is the stronger reason
to move. Deferred, not urgent — the feature is off by default.

Full analysis and the accept decision: `P1-06-cargo-deny-results.md` (2026-08-24).
