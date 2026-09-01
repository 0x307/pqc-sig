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

**None currently.** `advisories.ignore` in `deny.toml` is deliberately empty: nothing is
suppressed, so a new advisory landing on any dependency changes the `cargo-deny` output
immediately rather than being silently absorbed.

**Resolved 2026-09-01:** the `fndsa` feature previously bound FN-DSA/Falcon via
`pqcrypto-falcon`, a C FFI wrapper around a PQClean reference implementation. PQClean —
the upstream C implementation project — [is being archived in or after July
2026](https://github.com/PQClean/PQClean/issues/604), which put three advisories on the
`fndsa` feature (`pqcrypto-falcon` itself, plus `pqcrypto-internals` and `pqcrypto-traits`
transitively): RUSTSEC-2026-0165, RUSTSEC-2026-0163, RUSTSEC-2026-0162. None was a known
vulnerability — all three were "unmaintained upstream" advisories, and all three were
already gated behind the non-default `fndsa` feature, so a default `cargo build`/`cargo
test` never linked any of them.

The `fndsa` feature was migrated from `pqcrypto-falcon` to
[`fn-dsa`](https://crates.io/crates/fn-dsa) (Thomas Pornin, the original Falcon reference
author) — pure Rust, actively maintained, and `wasm32-unknown-unknown`-compatible, which
`pqcrypto-falcon`'s C FFI binding never was. This resolves all three advisories directly
rather than accepting them, and removes the C-FFI/non-WASM limitation as a side effect.
