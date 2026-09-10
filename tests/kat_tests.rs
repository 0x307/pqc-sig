//! Known-answer test (KAT) consumer for `pqc-sig` 0.4.0 (S-5: published KAT
//! vectors, executed on every `cargo test`).
//!
//! Loads every `tests/vectors/*.json` via `include_str!` (so the vectors ship
//! inside the packaged crate and this test works fully offline, with no
//! network access and no external files needed at test time — see
//! `tests/vectors/README.md` for provenance and regeneration instructions).
//!
//! For each vector, depending on `mode`:
//! - `"keygen"`: derive the public key from `seed`/`sk` and compare against
//!   the vector's `pk`.
//! - `"pure"` / `"ctx"` / `"prehash"`: verify the signature against `pk` and
//!   assert the result matches `expect`. When `seed`/`sk` is present *and*
//!   `expect == "valid"`, additionally re-sign deterministically and assert
//!   the signature is byte-identical to the vector's `signature` (this is
//!   the actual "known answer" check — regenerating must reproduce the exact
//!   same bytes).
//!
//! Run with `cargo test --test kat_tests -- --nocapture` to see the
//! per-file vector counts.

use std::collections::BTreeMap;

use serde::Deserialize;

use pqc_sig::prehash::PreHash;
use pqc_sig::{
    MlDsa44Keypair, MlDsa65Keypair, MlDsa87Keypair, SigAlgorithm, SigPublicKey, SigResult,
    Signature, SlhDsaSha2_128fKeypair, SlhDsaSha2_128sKeypair, SlhDsaSha2_192fKeypair,
    SlhDsaSha2_192sKeypair, SlhDsaSha2_256fKeypair, SlhDsaSha2_256sKeypair, SlhDsaShake128sKeypair,
};

#[derive(Deserialize)]
struct VectorFile {
    algorithm: String,
    #[allow(dead_code)]
    source: String,
    #[allow(dead_code)]
    generated_by: String,
    #[allow(dead_code)]
    spec: String,
    vectors: Vec<VectorEntry>,
}

#[derive(Deserialize)]
struct VectorEntry {
    id: String,
    mode: String,
    seed: Option<String>,
    sk: Option<String>,
    pk: String,
    ctx: String,
    prehash: Option<String>,
    message: String,
    #[allow(dead_code)]
    digest: Option<String>,
    signature: String,
    expect: String,
    #[allow(dead_code)]
    note: String,
}

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap_or_else(|e| panic!("bad hex {s:?}: {e}"))
}

fn name_to_prehash(name: &str) -> PreHash {
    match name {
        "SHA-256" => PreHash::Sha256,
        "SHA-384" => PreHash::Sha384,
        "SHA-512" => PreHash::Sha512,
        "SHA3-256" => PreHash::Sha3_256,
        "SHA3-384" => PreHash::Sha3_384,
        "SHA3-512" => PreHash::Sha3_512,
        "SHAKE128" => PreHash::Shake128,
        "SHAKE256" => PreHash::Shake256,
        other => panic!("kat_tests: unrecognized prehash name {other:?}"),
    }
}

/// Shared per-algorithm operations needed by the KAT runner. A local trait
/// (defined only in this test binary) delegating to each keypair type's
/// existing inherent methods — no crate API change.
trait KatAlg: Sized {
    fn from_key_bytes(bytes: &[u8]) -> SigResult<Self>;
    fn pubkey(&self) -> SigPublicKey;
    fn sign_pure(&self, msg: &[u8]) -> SigResult<Signature>;
    fn sign_ctx(&self, ctx: &[u8], msg: &[u8]) -> SigResult<Signature>;
    fn sign_prehash(&self, ctx: &[u8], hash: PreHash, digest: &[u8]) -> SigResult<Signature>;
    fn verify_pure(pk: &SigPublicKey, msg: &[u8], sig: &Signature) -> SigResult<()>;
    fn verify_ctx(pk: &SigPublicKey, ctx: &[u8], msg: &[u8], sig: &Signature) -> SigResult<()>;
    fn verify_prehash(
        pk: &SigPublicKey,
        ctx: &[u8],
        hash: PreHash,
        digest: &[u8],
        sig: &Signature,
    ) -> SigResult<()>;
}

macro_rules! impl_kat_alg {
    ($ty:ty) => {
        impl KatAlg for $ty {
            fn from_key_bytes(bytes: &[u8]) -> SigResult<Self> {
                <$ty>::from_secret_key_bytes(bytes)
            }
            fn pubkey(&self) -> SigPublicKey {
                self.public_key()
            }
            fn sign_pure(&self, msg: &[u8]) -> SigResult<Signature> {
                self.sign_deterministic(msg)
            }
            fn sign_ctx(&self, ctx: &[u8], msg: &[u8]) -> SigResult<Signature> {
                self.sign_ctx_deterministic(ctx, msg)
            }
            fn sign_prehash(&self, ctx: &[u8], hash: PreHash, digest: &[u8]) -> SigResult<Signature> {
                self.sign_prehash_deterministic(ctx, hash, digest)
            }
            fn verify_pure(pk: &SigPublicKey, msg: &[u8], sig: &Signature) -> SigResult<()> {
                <$ty>::verify(pk, msg, sig)
            }
            fn verify_ctx(pk: &SigPublicKey, ctx: &[u8], msg: &[u8], sig: &Signature) -> SigResult<()> {
                <$ty>::verify_ctx(pk, ctx, msg, sig)
            }
            fn verify_prehash(
                pk: &SigPublicKey,
                ctx: &[u8],
                hash: PreHash,
                digest: &[u8],
                sig: &Signature,
            ) -> SigResult<()> {
                <$ty>::verify_prehash(pk, ctx, hash, digest, sig)
            }
        }
    };
}

impl_kat_alg!(MlDsa44Keypair);
impl_kat_alg!(MlDsa65Keypair);
impl_kat_alg!(MlDsa87Keypair);
impl_kat_alg!(SlhDsaSha2_128sKeypair);
impl_kat_alg!(SlhDsaSha2_128fKeypair);
impl_kat_alg!(SlhDsaSha2_192sKeypair);
impl_kat_alg!(SlhDsaSha2_192fKeypair);
impl_kat_alg!(SlhDsaSha2_256sKeypair);
impl_kat_alg!(SlhDsaSha2_256fKeypair);
impl_kat_alg!(SlhDsaShake128sKeypair);

/// Run every vector in `file` against algorithm `K`, returning the count run.
fn run_file<K: KatAlg>(file_name: &str, algo: SigAlgorithm, json: &str) -> usize {
    let vf: VectorFile = serde_json::from_str(json)
        .unwrap_or_else(|e| panic!("{file_name}: failed to parse: {e}"));
    assert_eq!(vf.algorithm, algo.as_str(), "{file_name}: algorithm field mismatch");

    for v in &vf.vectors {
        run_vector::<K>(file_name, algo, v);
    }
    vf.vectors.len()
}

fn run_vector<K: KatAlg>(file_name: &str, algo: SigAlgorithm, v: &VectorEntry) {
    let ctx = unhex(&v.ctx);
    let msg = unhex(&v.message);
    let pk_bytes = unhex(&v.pk);
    let pk = SigPublicKey::new(algo, pk_bytes);

    match v.mode.as_str() {
        "keygen" => {
            let key_bytes = v
                .seed
                .as_deref()
                .or(v.sk.as_deref())
                .unwrap_or_else(|| panic!("{file_name}/{}: keygen vector missing seed/sk", v.id));
            let kp = K::from_key_bytes(&unhex(key_bytes))
                .unwrap_or_else(|e| panic!("{file_name}/{}: from_key_bytes failed: {e:?}", v.id));
            let derived = hex::encode(kp.pubkey().bytes);
            assert_eq!(derived, v.pk, "{file_name}/{}: derived pk mismatch", v.id);
        }
        "pure" | "ctx" | "prehash" => {
            let sig_bytes = unhex(&v.signature);
            let sig = Signature::new(algo, sig_bytes);

            let result = match v.mode.as_str() {
                "pure" => K::verify_pure(&pk, &msg, &sig),
                "ctx" => K::verify_ctx(&pk, &ctx, &msg, &sig),
                "prehash" => {
                    let hash_name = v
                        .prehash
                        .as_deref()
                        .unwrap_or_else(|| panic!("{file_name}/{}: prehash vector missing prehash field", v.id));
                    let hash = name_to_prehash(hash_name);
                    let digest = unhex(
                        v.digest
                            .as_deref()
                            .unwrap_or_else(|| panic!("{file_name}/{}: prehash vector missing digest field", v.id)),
                    );
                    K::verify_prehash(&pk, &ctx, hash, &digest, &sig)
                }
                _ => unreachable!(),
            };

            match v.expect.as_str() {
                "valid" => {
                    result.unwrap_or_else(|e| {
                        panic!("{file_name}/{}: expected valid, verify failed: {e:?}", v.id)
                    });
                }
                "invalid" => {
                    assert!(
                        result.is_err(),
                        "{file_name}/{}: expected invalid, verify unexpectedly succeeded",
                        v.id
                    );
                }
                other => panic!("{file_name}/{}: unknown expect value {other:?}", v.id),
            }

            // Regression / reproducibility check: if we have the signing key
            // and this vector is a genuine positive, re-signing deterministically
            // must reproduce the exact same signature bytes.
            if v.expect == "valid" {
                if let Some(key_hex) = v.seed.as_deref().or(v.sk.as_deref()) {
                    let kp = K::from_key_bytes(&unhex(key_hex)).unwrap_or_else(|e| {
                        panic!("{file_name}/{}: from_key_bytes failed: {e:?}", v.id)
                    });
                    let resigned = match v.mode.as_str() {
                        "pure" => kp.sign_pure(&msg),
                        "ctx" => kp.sign_ctx(&ctx, &msg),
                        "prehash" => {
                            let hash = name_to_prehash(v.prehash.as_deref().unwrap());
                            let digest = unhex(v.digest.as_deref().unwrap());
                            kp.sign_prehash(&ctx, hash, &digest)
                        }
                        _ => unreachable!(),
                    }
                    .unwrap_or_else(|e| panic!("{file_name}/{}: re-sign failed: {e:?}", v.id));
                    assert_eq!(
                        hex::encode(resigned.bytes),
                        v.signature,
                        "{file_name}/{}: re-signed signature is not byte-identical to the published KAT",
                        v.id
                    );
                }
            }
        }
        other => panic!("{file_name}/{}: unknown mode {other:?}", v.id),
    }
}

#[test]
fn kat_ml_dsa_44() {
    let n = run_file::<MlDsa44Keypair>(
        "ml_dsa_44.json",
        SigAlgorithm::MlDsa44,
        include_str!("vectors/ml_dsa_44.json"),
    );
    println!("kat_tests: ml_dsa_44.json — {n} vectors");
    assert!(n >= 20, "ml_dsa_44.json: expected at least 20 vectors, got {n}");
}

#[test]
fn kat_ml_dsa_65() {
    let n = run_file::<MlDsa65Keypair>(
        "ml_dsa_65.json",
        SigAlgorithm::MlDsa65,
        include_str!("vectors/ml_dsa_65.json"),
    );
    println!("kat_tests: ml_dsa_65.json — {n} vectors");
    assert!(n >= 20, "ml_dsa_65.json: expected at least 20 vectors, got {n}");
}

#[test]
fn kat_ml_dsa_87() {
    let n = run_file::<MlDsa87Keypair>(
        "ml_dsa_87.json",
        SigAlgorithm::MlDsa87,
        include_str!("vectors/ml_dsa_87.json"),
    );
    println!("kat_tests: ml_dsa_87.json — {n} vectors");
    assert!(n >= 20, "ml_dsa_87.json: expected at least 20 vectors, got {n}");
}

#[test]
fn kat_slh_dsa_sha2_128s() {
    let n = run_file::<SlhDsaSha2_128sKeypair>(
        "slh_dsa_sha2_128s.json",
        SigAlgorithm::SlhDsaSha2_128s,
        include_str!("vectors/slh_dsa_sha2_128s.json"),
    );
    println!("kat_tests: slh_dsa_sha2_128s.json — {n} vectors");
    assert!(n >= 4);
}

#[test]
fn kat_slh_dsa_sha2_128f() {
    let n = run_file::<SlhDsaSha2_128fKeypair>(
        "slh_dsa_sha2_128f.json",
        SigAlgorithm::SlhDsaSha2_128f,
        include_str!("vectors/slh_dsa_sha2_128f.json"),
    );
    println!("kat_tests: slh_dsa_sha2_128f.json — {n} vectors");
    assert!(n >= 4);
}

#[test]
fn kat_slh_dsa_sha2_192s() {
    let n = run_file::<SlhDsaSha2_192sKeypair>(
        "slh_dsa_sha2_192s.json",
        SigAlgorithm::SlhDsaSha2_192s,
        include_str!("vectors/slh_dsa_sha2_192s.json"),
    );
    println!("kat_tests: slh_dsa_sha2_192s.json — {n} vectors");
    assert!(n >= 4);
}

#[test]
fn kat_slh_dsa_sha2_192f() {
    let n = run_file::<SlhDsaSha2_192fKeypair>(
        "slh_dsa_sha2_192f.json",
        SigAlgorithm::SlhDsaSha2_192f,
        include_str!("vectors/slh_dsa_sha2_192f.json"),
    );
    println!("kat_tests: slh_dsa_sha2_192f.json — {n} vectors");
    assert!(n >= 4);
}

#[test]
fn kat_slh_dsa_sha2_256s() {
    let n = run_file::<SlhDsaSha2_256sKeypair>(
        "slh_dsa_sha2_256s.json",
        SigAlgorithm::SlhDsaSha2_256s,
        include_str!("vectors/slh_dsa_sha2_256s.json"),
    );
    println!("kat_tests: slh_dsa_sha2_256s.json — {n} vectors");
    assert!(n >= 4);
}

#[test]
fn kat_slh_dsa_sha2_256f() {
    let n = run_file::<SlhDsaSha2_256fKeypair>(
        "slh_dsa_sha2_256f.json",
        SigAlgorithm::SlhDsaSha2_256f,
        include_str!("vectors/slh_dsa_sha2_256f.json"),
    );
    println!("kat_tests: slh_dsa_sha2_256f.json — {n} vectors");
    assert!(n >= 4);
}

#[test]
fn kat_slh_dsa_shake_128s() {
    let n = run_file::<SlhDsaShake128sKeypair>(
        "slh_dsa_shake_128s.json",
        SigAlgorithm::SlhDsaShake128s,
        include_str!("vectors/slh_dsa_shake_128s.json"),
    );
    println!("kat_tests: slh_dsa_shake_128s.json — {n} vectors");
    assert!(n >= 4);
}

/// Meta-test: total vector count across every published file must be >= 100
/// (S-5's "100 known-answer tests published as files" requirement), and every
/// file must parse. Guards against accidental truncation/exclusion.
#[test]
fn kat_total_vector_count_at_least_100() {
    let files: BTreeMap<&str, &str> = BTreeMap::from([
        ("ml_dsa_44.json", include_str!("vectors/ml_dsa_44.json")),
        ("ml_dsa_65.json", include_str!("vectors/ml_dsa_65.json")),
        ("ml_dsa_87.json", include_str!("vectors/ml_dsa_87.json")),
        ("slh_dsa_sha2_128s.json", include_str!("vectors/slh_dsa_sha2_128s.json")),
        ("slh_dsa_sha2_128f.json", include_str!("vectors/slh_dsa_sha2_128f.json")),
        ("slh_dsa_sha2_192s.json", include_str!("vectors/slh_dsa_sha2_192s.json")),
        ("slh_dsa_sha2_192f.json", include_str!("vectors/slh_dsa_sha2_192f.json")),
        ("slh_dsa_sha2_256s.json", include_str!("vectors/slh_dsa_sha2_256s.json")),
        ("slh_dsa_sha2_256f.json", include_str!("vectors/slh_dsa_sha2_256f.json")),
        ("slh_dsa_shake_128s.json", include_str!("vectors/slh_dsa_shake_128s.json")),
    ]);

    let mut total = 0usize;
    for (name, json) in &files {
        let vf: VectorFile = serde_json::from_str(json).unwrap_or_else(|e| panic!("{name}: {e}"));
        println!("kat_tests: {name:28} {:3} vectors", vf.vectors.len());
        total += vf.vectors.len();
    }
    println!("kat_tests: TOTAL {total} vectors across {} files", files.len());
    assert!(total >= 100, "expected at least 100 published KAT vectors total, got {total}");
}
