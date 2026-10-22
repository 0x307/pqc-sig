# Stability and Cadence Policy

This project ships `0.x`. This document is the contract that comes with that: what counts as
a breaking change, how deprecations work, what release cadence you can expect, and what
support looks like. It's the same policy across every 0x307 repo in this family — the crypto
crates, the identity primitives, and the identity SDK.

---

## 1. Everything is 0.x

This project ships `0.x` until its own shape stops changing. `1.0.0` is tagged when the API
has stopped changing on contact with real use — a discovery, not a date on a roadmap. There's
no committed timeline to `1.0`.

Inside `0.x`, breaking changes are expected and allowed. What this policy fixes is how you'll
know one happened, and what you're owed when it does.

## 2. What counts as a breaking change

A change is breaking if code that compiled and ran correctly against the previous published
version might fail to compile, fail to run, or silently behave differently after the upgrade,
without you changing anything.

**Breaking, concretely:**

- Removing or renaming a public function, method, type, trait, or exported interface
- Changing a function's signature — parameter types, order, count, or return type
- Changing a type's public field set, or making a previously-public field private
- Changing the wire format or serialized shape of a type that crosses a process boundary
- Changing documented behavior of an existing call in a way that changes its output for the
  same input — including error-vs-success outcomes
- Tightening previously-permissive input validation such that previously-accepted input is
  now rejected
- Raising the Minimum Supported Rust Version (MSRV), or a package's minimum Node version
- Changing a default value that affects behavior (a default algorithm, a default feature
  flag's on/off state)

**Not breaking:**

- Adding a new public function, method, type, or optional field
- Widening an accepted input (accepting more than before, rejecting nothing that used to be
  accepted)
- Adding a new opt-in feature flag
- Performance improvements that don't change observable behavior
- Fixing a bug where the old behavior contradicted the documented behavior — the fix isn't
  breaking even though it changes output, because the old output was never the contract.
  These are called out in the changelog either way, since you may have been depending on the
  bug
- Internal refactors with no change to the public surface
- Documentation changes

**If it's ambiguous which side of this a change falls on, it's treated as breaking.** That's
the conservative default this policy exists to give you — the cost of an unnecessary minor
version bump is much lower than the cost of a silent break.

## 3. Deprecation before removal

Nothing is deleted without a deprecation cycle first:

1. The item is marked deprecated in a minor release, with the changelog entry stating what to
   migrate to.
2. It stays functional, with a working migration path documented, for **at least one full
   minor version** after the deprecation lands.
3. Removal happens in a later minor or major release, called out explicitly in that release's
   changelog as a completed removal.

One minor version is a floor, not a target — a deprecation with a non-obvious migration gets
more notice.

## 4. Every breaking change gets a changelog entry with a migration note

Not just "breaking: renamed `foo` to `bar`" — a migration note means you can read the entry
and know what to change in your own code without opening an issue to ask. Minimum bar: old
signature/name, new signature/name, and a one-line reason if it isn't obvious.

The `CHANGELOG.md` is the authoritative record of breaking changes — not commit messages, not
GitHub release notes alone.

## 5. Release cadence

**A release ships when there's something worth releasing — a fix, a feature, or a breaking
change that's been sitting long enough to be worth cutting a version for — and, independent of
that, at minimum once every 6 weeks.**

If nothing shipped in a given six-week window, the minimum release is a changelog-only release
stating that explicitly ("no functional changes this cycle") rather than silence. Silence is
what makes a 0.x project look abandoned; a shipped no-op doesn't.

This cadence is a floor, not a promise of frequency above it. Faster is normal, especially
early. The floor is what's meant to hold indefinitely, including through a slow stretch.

## 6. Versions and support windows

### We never yank

No published version is ever yanked. That includes versions with a security bug. We fix
forward: we ship a patched release and file a [RustSec](https://rustsec.org/) advisory that
names the affected versions and the fixed one. `cargo audit` and `cargo deny` then flag the
affected versions in your build, so you learn about the problem and the fix together.

### More than one line can be live

A line is a `0.x` minor, such as 0.4.x or 0.5.x. More than one line may be live at once.
The current line gets every fix and feature. A legacy line gets security patches only.

### A legacy line lasts 6 months

When a new line ships, the line before it becomes legacy. It gets security patches for
6 months after its successor ships. After that it is marked unsupported in the table below.
An unsupported line gets no more patches, but it stays on crates.io and stays downloadable.
Nothing that builds against it stops building.

### Support table for `pqc-sig`

| Line | Latest | Status | Security patches until |
|---|---|---|---|
| 0.5.x | 0.5.0 | Current | Until it becomes legacy |
| 0.4.x | 0.4.2 | Legacy, supported | 2027-05-31 |

0.4.x gets a longer window than 6 months from 0.5.0 (2026-09-24). The 0x307 crates that
depend on `pqc-sig` move to 0.5 by about 2026-11-16. The 0.4.x window runs 6 months from
then, rounded up to the end of the month.

Versions yanked before 2026-10-22 are not covered by this policy. Those are 0.1.0, 0.2.0,
0.2.1, 0.3.0, 0.3.1, 0.4.0 and 0.4.1. They stay yanked and get no patches. If you are on one
of them, move to 0.4.2 or 0.5.x.

### Moving from 0.4 to 0.5

The full record is the [0.5.0 entry in `CHANGELOG.md`](./CHANGELOG.md#050---2026-09-24).
In short:

- **Default features:** nothing changes. Bump the version and rebuild.
- **`default-features = false`:** ML-DSA and SLH-DSA moved behind the `ml-dsa` and
  `slh-dsa` features. Add the ones you use:

  ```toml
  # 0.4
  pqc-sig = { version = "0.4", default-features = false }
  # 0.5
  pqc-sig = { version = "0.5", default-features = false, features = ["ml-dsa", "slh-dsa"] }
  ```

  Without them, `fips204`, `fips205` and the `MlDsa*`/`SlhDsa*` keypair re-exports don't
  exist. The build fails with an unresolved import. It does not behave differently.
- **`hybrid`** now implies `ml-dsa`.
- **Wire encodings are byte-identical to 0.4.2.** Multikey, public key JSON, signature
  base64url, signature JSON and signed-message JSON all match for all 17 algorithms.
  `tests/encoding_vectors.rs` checks this against hashes generated by 0.4.2. Keys and
  signatures made by 0.4.2 work with 0.5, and the other way round.

## 7. Support posture

**Best-effort, no SLA, single named maintainer** — see `README.md` for who that is right now.
There's no team and no on-call rotation behind this project. In practice:

- Issues and PRs are triaged (labeled, acknowledged, or closed with a reason) on a
  best-effort basis, with no committed response time for general issues.
- The one exception is the **security contact** in `SECURITY.md`: reports there are
  acknowledged within **5 business days**.
- "Best-effort" means exactly that, not a soft-pedaled response-time promise. If that changes,
  this document changes with it.

## 8. Where this applies

This policy is shared across every repo in this family, not restated per repo. Each repo's
`SECURITY.md` and `CHANGELOG.md` reference this document rather than duplicating it.
