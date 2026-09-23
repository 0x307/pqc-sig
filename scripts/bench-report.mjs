#!/usr/bin/env node
// Generate BENCHMARKS.md from a criterion run.
//
// The table is generated, never written by hand, because a published number
// and the harness that produced it must not be able to drift apart. If you
// want to change what the table says, change what gets measured.
//
//   cargo bench --features fndsa --bench signatures
//   node scripts/bench-report.mjs > BENCHMARKS.md
//
// Reads criterion's own estimates.json rather than parsing its console output:
// the JSON carries the median and a 95% confidence interval, so the table can
// report spread instead of a single number pretending to be exact.
//
// Requires node. Generating the report is a maintainer task; running the
// benchmarks is not, and needs nothing but cargo.

import { readFileSync, readdirSync, existsSync, statSync } from "node:fs";
import { execSync } from "node:child_process";
import { join } from "node:path";

const ROOT = new URL("..", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1");
const CRIT = join(ROOT, "target", "criterion");

function sh(cmd, fallback = "unknown") {
  try {
    return execSync(cmd, { cwd: ROOT, stdio: ["ignore", "pipe", "ignore"] })
      .toString()
      .trim();
  } catch {
    return fallback;
  }
}

/** Nanoseconds to a human figure, with the unit chosen per value. */
function fmt(ns) {
  if (ns < 1_000) return `${ns.toFixed(1)} ns`;
  if (ns < 1_000_000) return `${(ns / 1_000).toFixed(1)} µs`;
  if (ns < 1_000_000_000) return `${(ns / 1_000_000).toFixed(2)} ms`;
  return `${(ns / 1_000_000_000).toFixed(2)} s`;
}

/** Walk target/criterion/<group>/<bench>/new/estimates.json. */
function collect() {
  if (!existsSync(CRIT)) return [];
  const out = [];
  for (const group of readdirSync(CRIT)) {
    const gdir = join(CRIT, group);
    if (!statSync(gdir).isDirectory() || group === "report") continue;
    for (const bench of readdirSync(gdir)) {
      const est = join(gdir, bench, "new", "estimates.json");
      if (!existsSync(est)) continue;
      const j = JSON.parse(readFileSync(est, "utf8"));

      // Criterion also records how far this run moved from the previous one,
      // as a fraction, in change/estimates.json. That number is the whole
      // stability story: the confidence interval above measures noise *within*
      // a run and is blind to the machine getting hotter between them.
      let drift = null;
      const chg = join(gdir, bench, "change", "estimates.json");
      if (existsSync(chg)) {
        try {
          drift = JSON.parse(readFileSync(chg, "utf8")).median.point_estimate;
        } catch {
          drift = null;
        }
      }

      out.push({
        group,
        bench,
        median: j.median.point_estimate,
        lo: j.median.confidence_interval.lower_bound,
        hi: j.median.confidence_interval.upper_bound,
        drift,
        mtime: statSync(est).mtimeMs,
      });
    }
  }
  return out;
}

// ── Only publish what this run measured ──────────────────────────────────────
//
// criterion never deletes results. A benchmark that is removed, renamed, or
// put behind a feature leaves its last numbers in target/criterion forever,
// and a naive reader of that directory publishes them as though they were
// measured today.
//
// That is not hypothetical: gating the hybrid behind a feature (0X3-194) left
// three stale entries that the first regenerated table published, dated the
// previous afternoon, for a group the run had not executed.
//
// Benchmarks within one run finish seconds apart. Two hours is far wider than
// any suite here takes and far narrower than the gap to a previous session.
//
// The limit of this heuristic, stated rather than discovered: two runs with
// *different feature sets* minutes apart are not distinguishable by mtime, so
// switching features and regenerating can still publish the earlier set.
// Clear `target/criterion` when changing which benchmarks exist. Whatever is
// excluded is printed to stderr, so the failure is at least visible.
const STALE_AFTER_MS = 2 * 60 * 60 * 1000;
const all = collect();
const newest = all.length ? Math.max(...all.map((r) => r.mtime)) : 0;
const stale = all.filter((r) => newest - r.mtime > STALE_AFTER_MS);
const rows = all.filter((r) => newest - r.mtime <= STALE_AFTER_MS);

if (stale.length) {
  // Loud, on stderr, because a silently dropped benchmark is the same class
  // of problem as a silently published one.
  console.error(
    `note: ignoring ${stale.length} stale result(s) from an earlier run:\n` +
      stale.map((r) => `  ${r.group}/${r.bench}`).join("\n")
  );
}

if (rows.length === 0) {
  console.error(
    "No criterion results found under target/criterion.\n" +
      "Run `cargo bench --features fndsa --bench signatures` first."
  );
  process.exit(1);
}

// Absent FN-DSA means the run was made without the feature, which would
// publish a table that silently omits the most expensive operation in the
// crate. Refuse rather than emit it.
if (!rows.some((r) => r.group.startsWith("fn-dsa"))) {
  console.error(
    "No FN-DSA results found, so this run did not measure it.\n" +
      "Re-run with `--features fndsa`. A table missing the crate's most\n" +
      "expensive operation is worse than no table."
  );
  process.exit(1);
}

const version = (readFileSync(join(ROOT, "Cargo.toml"), "utf8").match(
  /^version\s*=\s*"([^"]+)"/m
) || [, "unknown"])[1];

const commit = sh("git rev-parse --short HEAD");
const dirty = sh("git status --porcelain") !== "" ? " (working tree dirty)" : "";
const rustc = sh("rustc --version");
const date = new Date().toISOString().slice(0, 10);

let cpu = "unknown";
if (process.platform === "win32") {
  // Not `wmic`: it is deprecated and absent on current Windows, and returns
  // an empty string rather than failing, so the report would have quietly
  // said "unknown" forever.
  cpu =
    sh(
      'powershell -NoProfile -Command "(Get-CimInstance Win32_Processor).Name"',
      ""
    ).trim() || "unknown";
} else if (process.platform === "linux") {
  cpu = sh("grep -m1 'model name' /proc/cpuinfo", "").split(":").slice(1).join(":").trim();
} else if (process.platform === "darwin") {
  cpu = sh("sysctl -n machdep.cpu.brand_string");
}

const groups = [...new Set(rows.map((r) => r.group))].sort();

// ── Measurement stability ────────────────────────────────────────────────────
//
// A benchmark that moved between two runs of unchanged code measured the
// machine, not the code. This is the check that makes that visible in the
// document instead of only in whoever happened to run it twice.
//
// 5% is the threshold below which a figure is worth quoting. Above it, the
// number is a property of the conditions as much as of the code.
const DRIFT_LIMIT = 0.05;
const withDrift = rows.filter((r) => r.drift !== null);
const drifted = withDrift.filter((r) => Math.abs(r.drift) > DRIFT_LIMIT);
const worst = withDrift.length
  ? withDrift.reduce((a, b) => (Math.abs(b.drift) > Math.abs(a.drift) ? b : a))
  : null;
// A third of the suite moving is not a code change, it is the environment.
const UNSTABLE_RATIO = 0.33;
const unstable = withDrift.length > 0 && drifted.length / withDrift.length > UNSTABLE_RATIO;
const pct = (d) => `${d >= 0 ? "+" : ""}${(d * 100).toFixed(1)}%`;

let md = `# Benchmarks
${
  unstable
    ? `
> [!WARNING]
> **These figures are not stable on the machine that produced them.**
> ${drifted.length} of ${withDrift.length} benchmarks moved more than
> ${(DRIFT_LIMIT * 100).toFixed(0)}% against the previous run of the same code,
> the worst by **${pct(worst.drift)}** (\`${worst.group}/${worst.bench}\`).
>
> Treat the absolute numbers below as indicative only. Comparisons *within* a
> single run hold up better, because every operation throttles together — so
> "A is roughly twice B" survives what "A is 29.8 ms" does not.
>
> That is a weaker guarantee than it sounds, and it has already failed once
> here: a within-run comparison of two signing benchmarks was read as a 35%
> difference and published with an explanation, and it did not reproduce. For
> the signing groups specifically, anything under roughly 10% is below this
> harness's resolution. See **A result that needed explaining** below.
>
> See **Measurement stability** below.
`
    : ""
}

Generated by \`scripts/bench-report.mjs\` from a criterion run. **Do not edit
by hand** — a published number and the harness that produced it must not be
able to drift apart.

Reproduce:

\`\`\`bash
cargo bench --features fndsa --bench signatures
node scripts/bench-report.mjs > BENCHMARKS.md
\`\`\`

## Provenance

| | |
|---|---|
| Crate version | \`${version}\` |
| Commit | \`${commit}\`${dirty} |
| Date | ${date} |
| Toolchain | ${rustc} |
| CPU | ${cpu} |
| Profile | \`[profile.bench]\`: \`opt-level = 3\`, \`lto = true\`, \`codegen-units = 1\` |
| Harness | [\`benches/signatures.rs\`](benches/signatures.rs) |

**The profile matters.** This crate's \`[profile.release]\` sets
\`opt-level = "z"\`, and \`[profile.bench]\` would inherit it. The first run of
this suite did exactly that and published figures for a size-optimised build
with nothing saying so, which is why the bench profile is now stated
explicitly at \`opt-level = 3\`.

Worth being precise about what that release setting is and is not. \`pqc-sig\`
is an \`rlib\`; the WASM artifact and its JS bindings live in the sibling
\`pqc-sig-wasm\` crate. A library's own \`[profile.release]\` does not govern how
a consumer compiles it either — the consuming build's profile does. So
\`opt-level = "z"\` here affects this crate's *own* standalone builds, and
little else.

## What these are

**Real cryptography, on every line.** There are no deterministic stand-ins, no
mock adapters and no stub backends anywhere in this crate, so there is no
configuration in which a benchmark measures a hash instead of a lattice.
FN-DSA additionally sits behind a feature, and the harness **panics** rather
than skipping if that feature is off — a run that quietly measures nothing
still reports success, which is the failure this arrangement exists to
prevent.

Times are the **median** with a 95% confidence interval. Signing benchmarks
cycle 64 distinct messages: ML-DSA and FN-DSA both run rejection loops whose
iteration count depends on the input, so a single fixed message measures one
draw of a random variable rather than its average.

## Results

`;

for (const g of groups) {
  md += `### ${g}\n\n| Operation | Median | 95% CI |\n|---|---:|---|\n`;
  for (const r of rows.filter((x) => x.group === g).sort((a, b) => a.bench.localeCompare(b.bench))) {
    md += `| \`${r.bench}\` | ${fmt(r.median)} | ${fmt(r.lo)} – ${fmt(r.hi)} |\n`;
  }
  md += "\n";
}

md += `## A result that needed explaining, and turned out to be noise

An earlier revision of this document reported that \`sign_ctx_deterministic\`
was about 35% *faster* than \`sign_deterministic\` at ML-DSA-65 and -87, and
explained it by claiming the two reach different underlying APIs — that the
context variant goes through \`expanded_key()\` and the plain one does not, so
\`sign_deterministic\` was leaving time on the table.

That explanation was wrong, and so was the measurement. Both are recorded here
rather than deleted, because the wrong version was published (0X3-195).

**The two are the same code path.** In \`ml-dsa\` 0.1.1, \`SigningKey::try_sign\`
delegates to \`try_multipart_sign\`, which calls
\`self.expanded_key.raw_sign_deterministic(msg, &[])\`. \`expanded_key()\` is a
field accessor, not an expansion step. \`sign_deterministic(M, ctx)\` on the
expanded key calls \`raw_sign_deterministic(&[M], ctx)\`. With an empty context
these are the identical call, which is why
\`ml_dsa_65_empty_ctx_interoperates_with_legacy_api\` in
\`tests/ml_dsa_tests.rs\` passes: it asserts the two produce byte-identical
signatures. That test was already in the suite while this document claimed the
paths differed.

**The gap does not reproduce.** Measured directly at ML-DSA-65 under this
file's bench profile, over six independently generated keys and a
2048-message pool, with the machine warmed first and both orderings tried:

| | \`sign_ctx_deterministic\` ÷ \`sign_deterministic\` |
|---|---:|
| across six keys | 0.905, 0.923, 0.951, 0.957, 0.971, 1.030 |
| mean | 0.956 |

The ratio straddles 1.0, which is where it belongs. Mean signing cost over the
same six keys ranged 650–761 µs, so **key-to-key variation is larger than the
effect that was reported as a finding.**

**What the harness could not resolve.** Each group signs with one key and, at
the time, cycled only 64 messages. Deterministic signing fixes each message's
rejection-loop cost, so criterion's ten thousand iterations re-measured the
same 64 fixed costs over and over: the reported mean was an estimate from 64
samples no matter how long the run took. The pool is 512 now, but the
single-key limit remains, and it bounds what this table can say. **Differences
smaller than roughly 10% between two signing benchmarks are below the
resolution of this harness and are not findings.**

The run that produced the 35% figure also straddled a change to the harness
itself — the fix that introduced the message pool — so it compared two
different experiments. The drift table below carried shifts of ±90% at the
time. That was the signal the run was not comparable, and it was read as a
result instead.

The lesson kept: a benchmark result that contradicts what the algorithm can do
is a claim about the harness until proven otherwise. This one was published as
a property of the crate before anyone read the dependency's source.
`;

md += `## Measurement stability

Criterion's confidence intervals above measure variation **within** a run.
They say nothing about variation **between** runs, which on a thermally
constrained machine is much larger — and which looks identical to a real
regression.

This section reports the shift against the previous run of this suite. If the
code did not change in between, everything here is measurement noise by
definition.

${
  withDrift.length === 0
    ? "No previous run to compare against. Run `cargo bench` twice to populate this."
    : unstable
      ? `**Unstable.** ${drifted.length} of ${withDrift.length} benchmarks moved more than ${(DRIFT_LIMIT * 100).toFixed(0)}% against the previous run.

| Benchmark | Shift |
|---|---:|
${drifted
  .sort((a, b) => Math.abs(b.drift) - Math.abs(a.drift))
  .slice(0, 12)
  .map((r) => `| \`${r.group}/${r.bench}\` | ${pct(r.drift)} |`)
  .join("\n")}

A laptop under sustained benchmark load throttles, and the effect compounds
across a long suite: the operations measured last are measured on the hottest
silicon. Publishing an absolute figure taken this way states a property of the
afternoon rather than of the code.

**For figures intended to be quoted**, regenerate on a machine with a stable
clock: a desktop or server part with thermal headroom, idle, with frequency
scaling pinned. The numbers will differ, and they will mean something.`
      : drifted.length === 0
        ? `**Stable.** No benchmark moved more than ${(DRIFT_LIMIT * 100).toFixed(0)}% against the previous run${worst ? `; the largest shift was ${pct(worst.drift)} (\`${worst.group}/${worst.bench}\`)` : ""}.`
        : `**Mixed.** ${drifted.length} of ${withDrift.length} benchmarks moved more than ${(DRIFT_LIMIT * 100).toFixed(0)}% against the previous run, the worst by **${pct(worst.drift)}** (\`${worst.group}/${worst.bench}\`). That is below the ${(UNSTABLE_RATIO * 100).toFixed(0)}% of the suite it would take to call the whole run unstable, but it is not nothing.

| Benchmark | Shift |
|---|---:|
${drifted
  .sort((a, b) => Math.abs(b.drift) - Math.abs(a.drift))
  .slice(0, 12)
  .map((r) => `| \`${r.group}/${r.bench}\` | ${pct(r.drift)} |`)
  .join("\n")}

With the code unchanged between runs, shifts of this size come from the
machine or from the harness, not from the crate. Read these rows as this
suite's resolution limit rather than as results.`
}

## What is not measured

Stated so the absence is not mistaken for a result.

- **Key and signature sizes.** Fixed per parameter set and documented in the
  crate docs; they are not timings and do not belong in this table.
- **The \`hybrid\` feature.** It combines Ed25519 with ML-DSA-65, and Ed25519 is
  classical. It exists for interoperating with systems that have not moved yet
  and is deliberately not part of this crate's performance story.
- **WASM.** Every figure here is native. The WASM artifact is built by the
  sibling \`pqc-sig-wasm\` crate, which this suite does not measure at all.
- **Constant-time behaviour.** A median and a confidence interval say nothing
  about whether timing varies with secret data. That needs a different tool
  and a different claim.
- **Comparison against anything.** No classical baseline, no "PQC overhead"
  aggregate. An aggregate hides which operation moved, and a comparison
  invites a headline detached from the harness that produced it.
`;

process.stdout.write(md);
console.error(`ok: ${rows.length} benchmarks across ${groups.length} groups`);
