//! Every signature operation this crate offers, benched individually.
//!
//! # Why each operation gets its own name
//!
//! A single "signing" number tells you something got slower and nothing about
//! what. Every algorithm and operation is a separate `bench_function`, so a
//! regression localises to one line of output instead of one crate.
//!
//! # Why `benches/` and not `examples/`
//!
//! Because a file in `examples/` named `bench_something.rs` is a demo. It runs
//! when somebody remembers, prints whatever it prints, and is compared against
//! nothing. `cargo bench` has a baseline, a statistical model, and a stable
//! output format, and that difference is the whole point.
//!
//! # What is deliberately not here
//!
//! No comparison against classical signatures, and no aggregate "PQC overhead"
//! figure. An aggregate hides which operation moved, and a comparison invites a
//! headline number detached from the harness that produced it.
//!
//! # Message size
//!
//! 128 bytes, which is the scale of what actually gets signed in this family:
//! `aethel-auth`'s canonical `signing_input` is roughly 96 to 200 bytes. Size
//! barely moves these numbers anyway, because every scheme here hashes the
//! message before the lattice work begins. It is set once, here, so the figure
//! is comparable across runs rather than chosen per-benchmark.

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use rand::rngs::OsRng;

use pqc_sig::{MlDsa44Keypair, MlDsa65Keypair, MlDsa87Keypair};

/// Representative of what this family signs. See the module note.
const MESSAGE: &[u8; 128] = &[0x41; 128];

/// How many distinct messages the signing benchmarks cycle through.
///
/// Raised from 64 to 512 for 0X3-195. Deterministic signing gives each
/// message a *fixed* rejection-loop cost, so criterion running ten thousand
/// iterations over a 64-message pool re-measures the same 64 fixed costs a
/// hundred and fifty times over. The reported mean is an estimate from 64
/// samples however long the run takes: its error shrinks with the pool, and
/// not at all with criterion's iteration count.
const POOL: usize = 512;

/// A pool of distinct messages.
///
/// ML-DSA signing runs a rejection loop whose iteration count depends on the
/// message. Benching one fixed message under deterministic signing therefore
/// measures **a single draw of a random variable**, not its average — and the
/// draw is frozen, so the number is stable, repeatable and wrong.
///
/// The first version of this file did exactly that, and the symptom was
/// visible if you looked: `sign_ctx_deterministic` came out 2.4x *faster* than
/// `sign_deterministic` across all three parameter sets, which is impossible,
/// since it does the same work plus context binding. One fixed input happened
/// to be lucky and the other unlucky.
///
/// Cycling a pool averages over the distribution. The index arithmetic costs
/// nanoseconds against operations that cost hundreds of microseconds.
///
/// # The limit this still has, which bounds what the table can claim
///
/// Each group signs with **one key**, and signing cost varies by key. Measured
/// at ML-DSA-65 over six independently generated keys and a 2048-message pool,
/// mean signing cost ranged 650–761 µs, and the ratio between
/// `sign_ctx_deterministic` and `sign_deterministic` ranged 0.905 to 1.030 —
/// straddling 1.0, which is where it belongs, since both wrappers reach the
/// same `raw_sign_deterministic` and a context only changes `mu`.
///
/// So differences smaller than roughly 10% between two signing benchmarks are
/// below this harness's resolution and must not be read as findings. An
/// earlier revision read one such difference as a 35% speedup and published an
/// explanation for it. See BENCHMARKS.md.
fn message_pool() -> Vec<[u8; 128]> {
    (0..POOL)
        .map(|i| {
            let mut m = [0u8; 128];
            // Distinct and deterministic, so runs stay comparable to each
            // other. A CSPRNG here would make every run measure a different
            // set of rejection counts.
            for (j, b) in m.iter_mut().enumerate() {
                *b = ((i * 131 + j * 17) % 251) as u8;
            }
            m
        })
        .collect()
}

/// The purpose-separation context `aethel-core` passes on every signature.
/// Benched because it is the path actually taken, not the bare `sign`.
const CONTEXT: &[u8] = b"aethel-core/plp-present/v1";

/// ML-DSA, FIPS 204. The family's default signature.
fn ml_dsa(c: &mut Criterion) {
    macro_rules! bench_ml_dsa {
        ($name:literal, $kp:ty) => {{
            let mut group = c.benchmark_group($name);

            group.bench_function("keygen", |b| {
                b.iter(|| <$kp>::generate(&mut OsRng).expect("keygen"))
            });

            let kp = <$kp>::generate(&mut OsRng).expect("keygen");
            let pk = kp.public_key();
            let pool = message_pool();

            // Every signing benchmark cycles the pool. See `message_pool`:
            // a fixed message freezes the rejection-loop iteration count.
            let mut i = 0usize;
            group.bench_function("sign", |b| {
                b.iter(|| {
                    i = (i + 1) % POOL;
                    kp.sign(&mut OsRng, &pool[i]).expect("sign")
                })
            });

            // Deterministic signing skips the RNG, so the gap between this and
            // `sign` is the cost of randomness rather than of lattice work.
            let mut i = 0usize;
            group.bench_function("sign_deterministic", |b| {
                b.iter(|| {
                    i = (i + 1) % POOL;
                    kp.sign_deterministic(&pool[i]).expect("sign")
                })
            });

            // The path this family actually uses: FIPS 204 native context,
            // which is what makes a signature under one purpose structurally
            // unusable under another.
            let mut i = 0usize;
            group.bench_function("sign_ctx_deterministic", |b| {
                b.iter(|| {
                    i = (i + 1) % POOL;
                    kp.sign_ctx_deterministic(CONTEXT, &pool[i]).expect("sign")
                })
            });

            let sig = kp.sign_deterministic(MESSAGE).expect("sign");
            group.bench_function("verify", |b| {
                b.iter(|| <$kp>::verify(&pk, MESSAGE, &sig).expect("verify"))
            });

            let sig_ctx = kp.sign_ctx_deterministic(CONTEXT, MESSAGE).expect("sign");
            group.bench_function("verify_ctx", |b| {
                b.iter(|| <$kp>::verify_ctx(&pk, CONTEXT, MESSAGE, &sig_ctx).expect("verify"))
            });

            group.finish();
        }};
    }

    bench_ml_dsa!("ml-dsa-44", MlDsa44Keypair);
    bench_ml_dsa!("ml-dsa-65", MlDsa65Keypair);
    bench_ml_dsa!("ml-dsa-87", MlDsa87Keypair);
}

/// FN-DSA (Falcon), FIPS 206.
///
/// The reason this benchmark exists at all. FN-DSA signing is discrete
/// Gaussian sampling over an NTRU trapdoor, which is both the most expensive
/// operation in the crate and the one a trapdoor-based issuer would run once
/// per credential. Its cost against ML-DSA is a real input to that decision,
/// and until now nobody here had measured it.
///
/// Requires the `fndsa` feature. There is no silent skip: a benchmark that
/// quietly does not run still reports success.
#[cfg(feature = "fndsa")]
fn fn_dsa(c: &mut Criterion) {
    use pqc_sig::{FnDsa1024Keypair, FnDsa512Keypair};

    macro_rules! bench_fn_dsa {
        ($name:literal, $kp:ty) => {{
            let mut group = c.benchmark_group($name);

            // Keygen solves an NTRU equation and is far slower than signing.
            // Fewer samples so the suite stays runnable; the figure is still
            // comparable run to run.
            group.sample_size(10);
            group.bench_function("keygen", |b| {
                b.iter(|| <$kp>::generate(&mut OsRng).expect("keygen"))
            });
            group.sample_size(100);

            let kp = <$kp>::generate(&mut OsRng).expect("keygen");
            let pk = kp.public_key();
            let pool = message_pool();

            // This is the trapdoor sampler. It is the number the issuer
            // authentication decision turns on. Falcon's sampler also has
            // input-dependent cost, so it cycles the pool for the same reason
            // ML-DSA does.
            let mut i = 0usize;
            group.bench_function("sign", |b| {
                b.iter(|| {
                    i = (i + 1) % POOL;
                    kp.sign(&mut OsRng, &pool[i]).expect("sign")
                })
            });

            let mut i = 0usize;
            group.bench_function("sign_ctx", |b| {
                b.iter(|| {
                    i = (i + 1) % POOL;
                    kp.sign_ctx(&mut OsRng, CONTEXT, &pool[i]).expect("sign")
                })
            });

            let sig = kp.sign(&mut OsRng, MESSAGE).expect("sign");
            group.bench_function("verify", |b| {
                b.iter(|| <$kp>::verify(&pk, MESSAGE, &sig).expect("verify"))
            });

            group.finish();
        }};
    }

    bench_fn_dsa!("fn-dsa-512", FnDsa512Keypair);
    bench_fn_dsa!("fn-dsa-1024", FnDsa1024Keypair);
}

#[cfg(not(feature = "fndsa"))]
fn fn_dsa(_: &mut Criterion) {
    // Loud rather than absent. The alternative is a run that reports success
    // while having measured nothing, which is the failure this whole file is
    // written against.
    panic!(
        "the `fndsa` feature is off, so FN-DSA was not measured.\n\
         Run `cargo bench --features fndsa`, or `cargo bench --bench signatures \
         -- ml-dsa` to deliberately measure only ML-DSA."
    );
}

/// SLH-DSA, FIPS 205. Hash-based, so its cost is structurally different:
/// signing is slow and large, verification is comparatively cheap.
///
/// Only the 128-bit pair, and only to show the `s`/`f` trade-off. Benching
/// every parameter set would multiply the suite's runtime for very little.
fn slh_dsa(c: &mut Criterion) {
    use pqc_sig::{SlhDsaSha2_128fKeypair, SlhDsaSha2_128sKeypair};

    let mut group = c.benchmark_group("slh-dsa-sha2-128");
    // Both are orders of magnitude slower than the lattice schemes.
    group.sample_size(10);

    let f = SlhDsaSha2_128fKeypair::generate(&mut OsRng).expect("keygen");
    group.bench_function("128f/sign", |b| {
        b.iter_batched(
            || (),
            |_| f.sign(&mut OsRng, MESSAGE).expect("sign"),
            BatchSize::SmallInput,
        )
    });

    let s = SlhDsaSha2_128sKeypair::generate(&mut OsRng).expect("keygen");
    group.bench_function("128s/sign", |b| {
        b.iter_batched(
            || (),
            |_| s.sign(&mut OsRng, MESSAGE).expect("sign"),
            BatchSize::SmallInput,
        )
    });

    let f_pk = f.public_key();
    let f_sig = f.sign(&mut OsRng, MESSAGE).expect("sign");
    group.bench_function("128f/verify", |b| {
        b.iter(|| SlhDsaSha2_128fKeypair::verify(&f_pk, MESSAGE, &f_sig).expect("verify"))
    });

    group.finish();
}

criterion_group!(signatures, ml_dsa, fn_dsa, slh_dsa);
criterion_main!(signatures);
