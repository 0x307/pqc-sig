//! KAT vector generator / ACVP curator for `pqc-sig` 0.4.0 (S-5: published
//! known-answer test vectors).
//!
//! # Provenance (read this before touching `tests/vectors/*.json`)
//!
//! Two data sources are combined to build every file under `tests/vectors/`:
//!
//! 1. **Key material curated from NIST ACVP-Server.** `tests/vectors/acvp_source/`
//!    holds a small, hand-trimmed subset of
//!    `ML-DSA-keyGen-FIPS204`, `ML-DSA-sigVer-FIPS204`, and
//!    `SLH-DSA-keyGen-FIPS205` `internalProjection.json` (downloaded from
//!    <https://github.com/usnistgov/ACVP-Server>, `gen-val/json-files/.../internalProjection.json`,
//!    NIST public-domain test data). The full upstream files are 0.9-38 MB each;
//!    only a curated handful of test cases per parameter set are checked in
//!    here (tens of KB total) — see `tests/vectors/README.md` for the exact
//!    extraction method and how to re-derive them.
//! 2. **Deterministic self-generated vectors** produced by this crate itself
//!    (`pqc-sig` 0.4.0, RustCrypto `ml-dsa` 0.1.1 / `slh-dsa` 0.2.0-rc.5),
//!    signing over the ACVP-derived key material from (1). This crate's public
//!    `from_secret_key_bytes` only accepts the 32-byte ML-DSA seed (not
//!    ACVP `sigGen`'s *expanded* secret key), so ACVP `sigGen` vectors can't be
//!    replayed byte-for-byte through the public API — see
//!    `docs/GAP_VALIDATION.md` §7 and `tests/vectors/README.md`
//!    ("Why not ACVP sigGen directly"). ACVP `keyGen` (seed→pk) and `sigVer`
//!    (pk+message+signature→pass/fail) need no such translation, so those are
//!    used verbatim. SLH-DSA's ACVP `keyGen` "sk" field *is* this crate's own
//!    `from_secret_key_bytes` format (the raw FIPS 205 secret-key encoding), so
//!    SLH-DSA key material round-trips exactly.
//!
//! Every self-generated vector is produced by **deterministic** signing
//! (`sign_deterministic` / `sign_ctx_deterministic` / `sign_prehash_deterministic`)
//! over fixed inputs, so re-running this generator against the same
//! `acvp_source` files always reproduces byte-identical output — that is the
//! whole point of a KAT.
//!
//! # Usage
//!
//! This is a generator, not a build script: it never runs implicitly and
//! never overwrites anything unless given an explicit output directory.
//!
//! ```text
//! cargo run --example gen_kat_vectors -- tests/vectors
//! ```
//!
//! To verify reproducibility, run it against a scratch directory and diff:
//!
//! ```text
//! cargo run --example gen_kat_vectors -- /tmp/kat-regen
//! git diff --no-index tests/vectors/ml_dsa_65.json /tmp/kat-regen/ml_dsa_65.json
//! ```

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use pqc_sig::prehash::PreHash;
use pqc_sig::{
    MlDsa44Keypair, MlDsa65Keypair, MlDsa87Keypair, SigPublicKey, SigResult, Signature,
    SlhDsaSha2_128fKeypair, SlhDsaSha2_128sKeypair, SlhDsaSha2_192fKeypair,
    SlhDsaSha2_192sKeypair, SlhDsaSha2_256fKeypair, SlhDsaSha2_256sKeypair, SlhDsaShake128sKeypair,
};
use serde::Serialize;
use serde_json::Value;

// ── Output schema (mirrors tests/vectors/README.md exactly) ──────────────────

#[derive(Serialize)]
struct VectorFile {
    algorithm: String,
    source: String,
    generated_by: String,
    spec: String,
    vectors: Vec<VectorEntry>,
}

#[derive(Serialize)]
struct VectorEntry {
    id: String,
    mode: String,
    seed: Option<String>,
    sk: Option<String>,
    pk: String,
    ctx: String,
    prehash: Option<String>,
    message: String,
    digest: Option<String>,
    signature: String,
    expect: String,
    note: String,
}

// ── Fixed, deterministic message corpus ───────────────────────────────────────

fn fixed_pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i % 256) as u8).collect()
}

fn msg_empty() -> Vec<u8> { Vec::new() }
fn msg_one_byte() -> Vec<u8> { vec![0x41] }
fn msg_two_byte() -> Vec<u8> { vec![0x41, 0x42] }
fn msg_sixteen_byte() -> Vec<u8> { fixed_pattern(16) }
fn msg_thirty_two_byte() -> Vec<u8> { fixed_pattern(32) }
fn msg_thousand_byte() -> Vec<u8> { fixed_pattern(1000) }
fn msg_four_k() -> Vec<u8> { fixed_pattern(4096) }
fn msg_sentence() -> Vec<u8> { b"The quick brown fox jumps over the lazy dog.".to_vec() }

// ── Digest computation for prehash vectors (caller-hashes, per src/prehash.rs) ─

#[allow(unused_imports)]
fn compute_digest(hash: PreHash, msg: &[u8]) -> Vec<u8> {
    use sha2::Digest as _;
    use sha2::{Sha256, Sha384, Sha512};
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    use sha3::Digest as _;
    use sha3::{Sha3_256, Sha3_384, Sha3_512, Shake128, Shake256};

    match hash {
        PreHash::Sha256 => Sha256::digest(msg).to_vec(),
        PreHash::Sha384 => Sha384::digest(msg).to_vec(),
        PreHash::Sha512 => Sha512::digest(msg).to_vec(),
        PreHash::Sha3_256 => Sha3_256::digest(msg).to_vec(),
        PreHash::Sha3_384 => Sha3_384::digest(msg).to_vec(),
        PreHash::Sha3_512 => Sha3_512::digest(msg).to_vec(),
        PreHash::Shake128 => {
            let mut h = Shake128::default();
            h.update(msg);
            let mut out = [0u8; 32];
            h.finalize_xof().read(&mut out);
            out.to_vec()
        }
        PreHash::Shake256 => {
            let mut h = Shake256::default();
            h.update(msg);
            let mut out = [0u8; 64];
            h.finalize_xof().read(&mut out);
            out.to_vec()
        }
        // PreHash is #[non_exhaustive]; every variant that exists today is
        // handled above. A future upstream addition should fail loudly here
        // rather than silently mis-hash.
        _ => panic!("gen_kat_vectors: unhandled PreHash variant {hash:?} — add a compute_digest arm"),
    }
}

/// Map an ACVP `hashAlg` string (ML-DSA-sigVer-FIPS204) to our [`PreHash`].
fn map_acvp_hash(name: &str) -> PreHash {
    match name {
        "SHA2-256" => PreHash::Sha256,
        "SHA2-384" => PreHash::Sha384,
        "SHA2-512" => PreHash::Sha512,
        "SHA3-256" => PreHash::Sha3_256,
        "SHA3-384" => PreHash::Sha3_384,
        "SHA3-512" => PreHash::Sha3_512,
        "SHAKE-128" => PreHash::Shake128,
        "SHAKE-256" => PreHash::Shake256,
        other => panic!("unsupported/unmapped ACVP hashAlg: {other}"),
    }
}

// ── Shared per-algorithm operations (local trait; thin delegation to the ───────
//    existing inherent methods on each of the 10 keypair types — no crate API
//    change, this trait lives entirely in this example).

trait KatAlg: Sized {
    fn from_key_bytes(bytes: &[u8]) -> SigResult<Self>;
    fn pubkey(&self) -> SigPublicKey;
    fn sign_pure(&self, msg: &[u8]) -> SigResult<Signature>;
    fn sign_ctx(&self, ctx: &[u8], msg: &[u8]) -> SigResult<Signature>;
    fn sign_prehash(&self, ctx: &[u8], hash: PreHash, digest: &[u8]) -> SigResult<Signature>;
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

// ── ACVP source loading ───────────────────────────────────────────────────────

fn load_json(path: &Path) -> Value {
    let s = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    serde_json::from_str(&s).unwrap_or_else(|e| panic!("failed to parse {}: {e}", path.display()))
}

// ── ML-DSA file builder ────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn build_ml_dsa_file<K: KatAlg>(
    ps: &str,
    spec: &str,
    keygen: &Value,
    sigver: &Value,
    prehash_candidates: &[PreHash],
) -> VectorFile {
    let mut vectors: Vec<VectorEntry> = Vec::new();
    let slug = ps.to_lowercase().replace('-', "_");

    let kg_entries = keygen["data"][ps]
        .as_array()
        .unwrap_or_else(|| panic!("no ACVP keyGen entries for {ps}"));

    // 1. keygen: seed -> pk, cross-checked against ACVP's own derived pk.
    for e in kg_entries.iter().take(2) {
        let tc_id = e["tcId"].as_u64().unwrap_or(0);
        let seed_hex = e["seed"].as_str().expect("seed").to_lowercase();
        let pk_hex = e["pk"].as_str().expect("pk").to_lowercase();
        let seed_bytes = hex::decode(&seed_hex).expect("hex seed");
        let kp = K::from_key_bytes(&seed_bytes).expect("keypair from ACVP seed");
        let derived_pk_hex = hex::encode(kp.pubkey().bytes);
        assert_eq!(
            derived_pk_hex, pk_hex,
            "{ps} keyGen tcId={tc_id}: derived pk does not match ACVP-published pk"
        );
        vectors.push(VectorEntry {
            id: format!("{slug}-keygen-{:04}", vectors.len() + 1),
            mode: "keygen".into(),
            seed: Some(seed_hex),
            sk: None,
            pk: pk_hex,
            ctx: String::new(),
            prehash: None,
            message: String::new(),
            digest: None,
            signature: String::new(),
            expect: "valid".into(),
            note: format!(
                "NIST ACVP-Server ML-DSA-keyGen-FIPS204 tcId={tc_id}: seed -> pk verified against the ACVP-published pk"
            ),
        });
    }

    // Self-generated pure/ctx/prehash/negative vectors, signed with the first
    // ACVP-derived seed above (external key material, self-generated signatures).
    let seed0_hex = kg_entries[0]["seed"].as_str().unwrap().to_lowercase();
    let seed0_tcid = kg_entries[0]["tcId"].as_u64().unwrap_or(0);
    let seed0 = hex::decode(&seed0_hex).unwrap();
    let kp = K::from_key_bytes(&seed0).expect("keypair from ACVP seed");
    let pk_hex = hex::encode(kp.pubkey().bytes);

    // 2. pure (8): fixed message corpus, empty ctx.
    let pure_msgs: [(&str, Vec<u8>); 8] = [
        ("empty", msg_empty()),
        ("one-byte", msg_one_byte()),
        ("two-byte", msg_two_byte()),
        ("sixteen-byte", msg_sixteen_byte()),
        ("thirty-two-byte", msg_thirty_two_byte()),
        ("thousand-byte", msg_thousand_byte()),
        ("sentence", msg_sentence()),
        ("four-kilobyte", msg_four_k()),
    ];
    for (label, msg) in &pure_msgs {
        let sig = kp.sign_pure(msg).expect("sign_pure");
        vectors.push(VectorEntry {
            id: format!("{slug}-pure-{:04}", vectors.len() + 1),
            mode: "pure".into(),
            seed: Some(seed0_hex.clone()),
            sk: None,
            pk: pk_hex.clone(),
            ctx: String::new(),
            prehash: None,
            message: hex::encode(msg),
            digest: None,
            signature: hex::encode(sig.bytes),
            expect: "valid".into(),
            note: format!(
                "self-generated deterministic (pqc-sig 0.4.0); message={label}; key=ACVP ML-DSA-keyGen-FIPS204 tcId={seed0_tcid}"
            ),
        });
    }

    // 3. ctx (6): empty, 1-byte, 16-byte, 32-byte, 254-byte, 255-byte (max).
    let ctx_cases: [(&str, Vec<u8>, Vec<u8>); 6] = [
        ("empty-ctx", Vec::new(), msg_sentence()),
        ("one-byte-ctx", vec![0x2A], msg_thirty_two_byte()),
        ("sixteen-byte-ctx", fixed_pattern(16), msg_sentence()),
        ("thirty-two-byte-ctx", fixed_pattern(32), msg_thousand_byte()),
        ("254-byte-ctx", fixed_pattern(254), msg_one_byte()),
        ("255-byte-ctx-max", fixed_pattern(255), msg_sentence()),
    ];
    for (label, ctx, msg) in &ctx_cases {
        let sig = kp.sign_ctx(ctx, msg).expect("sign_ctx");
        vectors.push(VectorEntry {
            id: format!("{slug}-ctx-{:04}", vectors.len() + 1),
            mode: "ctx".into(),
            seed: Some(seed0_hex.clone()),
            sk: None,
            pk: pk_hex.clone(),
            ctx: hex::encode(ctx),
            prehash: None,
            message: hex::encode(msg),
            digest: None,
            signature: hex::encode(sig.bytes),
            expect: "valid".into(),
            note: format!(
                "self-generated deterministic (pqc-sig 0.4.0); ctx={label} ({} bytes); key=ACVP ML-DSA-keyGen-FIPS204 tcId={seed0_tcid}",
                ctx.len()
            ),
        });
    }

    // 4. prehash (6): cycle through the hashes allowed at this security level.
    let mut ph_list: Vec<PreHash> = Vec::new();
    while ph_list.len() < 6 {
        for h in prehash_candidates {
            if ph_list.len() >= 6 {
                break;
            }
            ph_list.push(*h);
        }
    }
    for (i, hash) in ph_list.into_iter().enumerate() {
        let msg = if i < prehash_candidates.len() { msg_sentence() } else { msg_thousand_byte() };
        let digest = compute_digest(hash, &msg);
        let sig = kp.sign_prehash(&[], hash, &digest).expect("sign_prehash");
        vectors.push(VectorEntry {
            id: format!("{slug}-prehash-{:04}", vectors.len() + 1),
            mode: "prehash".into(),
            seed: Some(seed0_hex.clone()),
            sk: None,
            pk: pk_hex.clone(),
            ctx: String::new(),
            prehash: Some(hash.name().to_string()),
            message: hex::encode(&msg),
            digest: Some(hex::encode(&digest)),
            signature: hex::encode(sig.bytes),
            expect: "valid".into(),
            note: format!(
                "self-generated deterministic HashML-DSA (pqc-sig 0.4.0); hash={}; key=ACVP ML-DSA-keyGen-FIPS204 tcId={seed0_tcid}",
                hash.name()
            ),
        });
    }

    // 5. negative (3): self-generated tampering, independent of ACVP.
    {
        let msg = msg_sentence();
        let sig = kp.sign_pure(&msg).expect("sign_pure");
        let mut tampered = sig.bytes.clone();
        tampered[0] ^= 0x01;
        vectors.push(VectorEntry {
            id: format!("{slug}-sigver-neg-{:04}", vectors.len() + 1),
            mode: "pure".into(),
            seed: Some(seed0_hex.clone()),
            sk: None,
            pk: pk_hex.clone(),
            ctx: String::new(),
            prehash: None,
            message: hex::encode(&msg),
            digest: None,
            signature: hex::encode(tampered),
            expect: "invalid".into(),
            note: "self-generated: bit-flipped a valid pure signature (byte 0, bit 0)".into(),
        });
    }
    {
        let signed_ctx = fixed_pattern(16);
        let wrong_ctx = fixed_pattern(17);
        let msg = msg_sentence();
        let sig = kp.sign_ctx(&signed_ctx, &msg).expect("sign_ctx");
        vectors.push(VectorEntry {
            id: format!("{slug}-sigver-neg-{:04}", vectors.len() + 1),
            mode: "ctx".into(),
            seed: Some(seed0_hex.clone()),
            sk: None,
            pk: pk_hex.clone(),
            ctx: hex::encode(&wrong_ctx),
            prehash: None,
            message: hex::encode(&msg),
            digest: None,
            signature: hex::encode(sig.bytes),
            expect: "invalid".into(),
            note: "self-generated: valid signature made under a 16-byte ctx, verified against a different 17-byte ctx".into(),
        });
    }
    {
        let msg = msg_sentence();
        let sig = kp.sign_pure(&msg).expect("sign_pure");
        let mut tampered_msg = msg.clone();
        tampered_msg[0] ^= 0xFF;
        vectors.push(VectorEntry {
            id: format!("{slug}-sigver-neg-{:04}", vectors.len() + 1),
            mode: "pure".into(),
            seed: Some(seed0_hex.clone()),
            sk: None,
            pk: pk_hex.clone(),
            ctx: String::new(),
            prehash: None,
            message: hex::encode(&tampered_msg),
            digest: None,
            signature: hex::encode(sig.bytes),
            expect: "invalid".into(),
            note: "self-generated: valid signature verified against a tampered message (byte 0 flipped)".into(),
        });
    }

    // 6. Real ACVP sigVer cases (verify-only; no seed/sk to re-sign with —
    //    genuine external NIST test vectors, unmodified).
    if let Some(sv_list) = sigver["data"][ps].as_array() {
        for e in sv_list {
            let role = e["role"].as_str().unwrap_or("");
            let tg_id = e["tgId"].as_u64().unwrap_or(0);
            let tc_id = e["tcId"].as_u64().unwrap_or(0);
            let pk_hex = e["pk"].as_str().expect("pk").to_lowercase();
            let msg_hex = e["message"].as_str().expect("message").to_lowercase();
            let ctx_hex = e["context"].as_str().unwrap_or("").to_lowercase();
            let hash_alg = e["hashAlg"].as_str().unwrap_or("none");
            let sig_hex = e["signature"].as_str().expect("signature").to_lowercase();
            let passed = e["testPassed"].as_bool().unwrap_or(true);
            let reason = e["reason"].as_str().unwrap_or("");
            let ctx_len = hex::decode(&ctx_hex).map(|b| b.len()).unwrap_or(0);

            let (mode, prehash_name, digest_hex) = if hash_alg != "none" {
                let ph = map_acvp_hash(hash_alg);
                let msg_bytes = hex::decode(&msg_hex).expect("hex message");
                let digest = compute_digest(ph, &msg_bytes);
                ("prehash".to_string(), Some(ph.name().to_string()), Some(hex::encode(digest)))
            } else if ctx_len == 0 {
                ("pure".to_string(), None, None)
            } else {
                ("ctx".to_string(), None, None)
            };

            vectors.push(VectorEntry {
                id: format!("{slug}-acvp-sigver-{:04}", vectors.len() + 1),
                mode,
                seed: None,
                sk: None,
                pk: pk_hex,
                ctx: ctx_hex,
                prehash: prehash_name,
                message: msg_hex,
                digest: digest_hex,
                signature: sig_hex,
                expect: if passed { "valid".into() } else { "invalid".into() },
                note: format!(
                    "NIST ACVP-Server ML-DSA-sigVer-FIPS204 tgId={tg_id} tcId={tc_id} role={role}{}",
                    if reason.is_empty() { String::new() } else { format!("; reason={reason}") }
                ),
            });
        }
    }

    VectorFile {
        algorithm: ps.to_string(),
        source: "Keys (keygen/pure/ctx/prehash/negative vectors): NIST ACVP-Server ML-DSA-keyGen-FIPS204 seeds (github.com/usnistgov/ACVP-Server, gen-val/json-files/ML-DSA-keyGen-FIPS204/internalProjection.json), pk cross-checked at generation time; pure/ctx/prehash/negative signatures self-generated deterministically by pqc-sig 0.4.0 (RustCrypto ml-dsa 0.1.1) over that ACVP-derived key. acvp-sigver-* vectors: verbatim NIST ACVP-Server ML-DSA-sigVer-FIPS204 positive/negative cases (pk+message+context+signature+expected result), unmodified. See tests/vectors/README.md.".into(),
        generated_by: "examples/gen_kat_vectors.rs (pqc-sig 0.4.0) + curated NIST ACVP-Server data in tests/vectors/acvp_source/".into(),
        spec: spec.into(),
        vectors,
    }
}

// ── SLH-DSA file builder ──────────────────────────────────────────────────────

fn build_slh_dsa_file<K: KatAlg>(ps: &str, spec: &str, keygen: &Value, prehash: PreHash) -> VectorFile {
    let mut vectors: Vec<VectorEntry> = Vec::new();
    let slug = ps.to_lowercase().replace("slh-dsa-", "").replace('-', "_");

    let kg_entries = keygen["data"][ps]
        .as_array()
        .unwrap_or_else(|| panic!("no ACVP keyGen entries for {ps}"));

    for e in kg_entries.iter().take(2) {
        let tc_id = e["tcId"].as_u64().unwrap_or(0);
        let sk_hex = e["sk"].as_str().expect("sk").to_lowercase();
        let pk_hex = e["pk"].as_str().expect("pk").to_lowercase();
        let sk_bytes = hex::decode(&sk_hex).expect("hex sk");
        let kp = K::from_key_bytes(&sk_bytes).expect("keypair from ACVP sk");
        let derived_pk_hex = hex::encode(kp.pubkey().bytes);
        assert_eq!(
            derived_pk_hex, pk_hex,
            "{ps} keyGen tcId={tc_id}: derived pk does not match ACVP-published pk"
        );
        vectors.push(VectorEntry {
            id: format!("{slug}-keygen-{:04}", vectors.len() + 1),
            mode: "keygen".into(),
            seed: None,
            sk: Some(sk_hex),
            pk: pk_hex,
            ctx: String::new(),
            prehash: None,
            message: String::new(),
            digest: None,
            signature: String::new(),
            expect: "valid".into(),
            note: format!(
                "NIST ACVP-Server SLH-DSA-keyGen-FIPS205 tcId={tc_id}: sk (skSeed||skPrf||pkSeed||pkRoot) is byte-identical to this crate's from_secret_key_bytes encoding; pk cross-checked"
            ),
        });
    }

    let sk0_hex = kg_entries[0]["sk"].as_str().unwrap().to_lowercase();
    let sk0_tcid = kg_entries[0]["tcId"].as_u64().unwrap_or(0);
    let sk0 = hex::decode(&sk0_hex).unwrap();
    let kp = K::from_key_bytes(&sk0).expect("keypair from ACVP sk");
    let pk_hex = hex::encode(kp.pubkey().bytes);

    // pure
    {
        let msg = msg_sentence();
        let sig = kp.sign_pure(&msg).expect("sign_pure");
        vectors.push(VectorEntry {
            id: format!("{slug}-pure-{:04}", vectors.len() + 1),
            mode: "pure".into(),
            seed: None,
            sk: Some(sk0_hex.clone()),
            pk: pk_hex.clone(),
            ctx: String::new(),
            prehash: None,
            message: hex::encode(&msg),
            digest: None,
            signature: hex::encode(sig.bytes),
            expect: "valid".into(),
            note: format!(
                "self-generated deterministic (pqc-sig 0.4.0); key=ACVP SLH-DSA-keyGen-FIPS205 tcId={sk0_tcid}"
            ),
        });
    }

    // ctx
    {
        let ctx = fixed_pattern(16);
        let msg = msg_thousand_byte();
        let sig = kp.sign_ctx(&ctx, &msg).expect("sign_ctx");
        vectors.push(VectorEntry {
            id: format!("{slug}-ctx-{:04}", vectors.len() + 1),
            mode: "ctx".into(),
            seed: None,
            sk: Some(sk0_hex.clone()),
            pk: pk_hex.clone(),
            ctx: hex::encode(&ctx),
            prehash: None,
            message: hex::encode(&msg),
            digest: None,
            signature: hex::encode(sig.bytes),
            expect: "valid".into(),
            note: format!(
                "self-generated deterministic (pqc-sig 0.4.0); ctx=16 bytes; key=ACVP SLH-DSA-keyGen-FIPS205 tcId={sk0_tcid}"
            ),
        });
    }

    // prehash
    {
        let msg = msg_thirty_two_byte();
        let digest = compute_digest(prehash, &msg);
        let sig = kp.sign_prehash(&[], prehash, &digest).expect("sign_prehash");
        vectors.push(VectorEntry {
            id: format!("{slug}-prehash-{:04}", vectors.len() + 1),
            mode: "prehash".into(),
            seed: None,
            sk: Some(sk0_hex.clone()),
            pk: pk_hex.clone(),
            ctx: String::new(),
            prehash: Some(prehash.name().to_string()),
            message: hex::encode(&msg),
            digest: Some(hex::encode(&digest)),
            signature: hex::encode(sig.bytes),
            expect: "valid".into(),
            note: format!(
                "self-generated deterministic HashSLH-DSA (pqc-sig 0.4.0); hash={}; key=ACVP SLH-DSA-keyGen-FIPS205 tcId={sk0_tcid}",
                prehash.name()
            ),
        });
    }

    // negative
    {
        let msg = msg_sentence();
        let sig = kp.sign_pure(&msg).expect("sign_pure");
        let mut tampered = sig.bytes.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x80;
        vectors.push(VectorEntry {
            id: format!("{slug}-sigver-neg-{:04}", vectors.len() + 1),
            mode: "pure".into(),
            seed: None,
            sk: Some(sk0_hex.clone()),
            pk: pk_hex.clone(),
            ctx: String::new(),
            prehash: None,
            message: hex::encode(&msg),
            digest: None,
            signature: hex::encode(tampered),
            expect: "invalid".into(),
            note: "self-generated: bit-flipped a valid pure signature (last byte, high bit)".into(),
        });
    }

    VectorFile {
        algorithm: ps.to_string(),
        source: "Keys and all signatures: NIST ACVP-Server SLH-DSA-keyGen-FIPS205 sk/pk (github.com/usnistgov/ACVP-Server, gen-val/json-files/SLH-DSA-keyGen-FIPS205/internalProjection.json) loaded directly via this crate's from_secret_key_bytes (the ACVP sk encoding matches it exactly); pk cross-checked at generation time. pure/ctx/prehash/negative signatures self-generated deterministically by pqc-sig 0.4.0 (RustCrypto slh-dsa 0.2.0-rc.5) over that ACVP-derived key. See tests/vectors/README.md.".into(),
        generated_by: "examples/gen_kat_vectors.rs (pqc-sig 0.4.0) + curated NIST ACVP-Server data in tests/vectors/acvp_source/".into(),
        spec: spec.into(),
        vectors,
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("usage: cargo run --example gen_kat_vectors -- <output-dir>");
        eprintln!();
        eprintln!("Writes tests/vectors/*.json deterministically from the curated ACVP");
        eprintln!("source files in tests/vectors/acvp_source/ plus self-generated");
        eprintln!("pure/ctx/prehash/negative vectors. See tests/vectors/README.md.");
        std::process::exit(1);
    }
    let out_dir = PathBuf::from(&args[1]);
    fs::create_dir_all(&out_dir).expect("create output dir");

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let acvp_dir = manifest_dir.join("tests").join("vectors").join("acvp_source");

    let ml_keygen = load_json(&acvp_dir.join("ml_dsa_keygen.json"));
    let ml_sigver = load_json(&acvp_dir.join("ml_dsa_sigver.json"));
    let slh_keygen = load_json(&acvp_dir.join("slh_dsa_keygen.json"));

    let files: Vec<(&str, VectorFile)> = vec![
        (
            "ml_dsa_44.json",
            build_ml_dsa_file::<MlDsa44Keypair>(
                "ML-DSA-44",
                "FIPS 204",
                &ml_keygen,
                &ml_sigver,
                &[
                    PreHash::Sha256, PreHash::Sha384, PreHash::Sha512,
                    PreHash::Sha3_256, PreHash::Sha3_384, PreHash::Shake128,
                ],
            ),
        ),
        (
            "ml_dsa_65.json",
            build_ml_dsa_file::<MlDsa65Keypair>(
                "ML-DSA-65",
                "FIPS 204",
                &ml_keygen,
                &ml_sigver,
                &[PreHash::Sha384, PreHash::Sha512, PreHash::Sha3_384, PreHash::Sha3_512, PreHash::Shake256],
            ),
        ),
        (
            "ml_dsa_87.json",
            build_ml_dsa_file::<MlDsa87Keypair>(
                "ML-DSA-87",
                "FIPS 204",
                &ml_keygen,
                &ml_sigver,
                &[PreHash::Sha512, PreHash::Sha3_512, PreHash::Shake256],
            ),
        ),
        (
            "slh_dsa_sha2_128s.json",
            build_slh_dsa_file::<SlhDsaSha2_128sKeypair>("SLH-DSA-SHA2-128s", "FIPS 205", &slh_keygen, PreHash::Sha256),
        ),
        (
            "slh_dsa_sha2_128f.json",
            build_slh_dsa_file::<SlhDsaSha2_128fKeypair>("SLH-DSA-SHA2-128f", "FIPS 205", &slh_keygen, PreHash::Sha256),
        ),
        (
            "slh_dsa_sha2_192s.json",
            build_slh_dsa_file::<SlhDsaSha2_192sKeypair>("SLH-DSA-SHA2-192s", "FIPS 205", &slh_keygen, PreHash::Sha384),
        ),
        (
            "slh_dsa_sha2_192f.json",
            build_slh_dsa_file::<SlhDsaSha2_192fKeypair>("SLH-DSA-SHA2-192f", "FIPS 205", &slh_keygen, PreHash::Sha384),
        ),
        (
            "slh_dsa_sha2_256s.json",
            build_slh_dsa_file::<SlhDsaSha2_256sKeypair>("SLH-DSA-SHA2-256s", "FIPS 205", &slh_keygen, PreHash::Sha512),
        ),
        (
            "slh_dsa_sha2_256f.json",
            build_slh_dsa_file::<SlhDsaSha2_256fKeypair>("SLH-DSA-SHA2-256f", "FIPS 205", &slh_keygen, PreHash::Sha512),
        ),
        (
            "slh_dsa_shake_128s.json",
            build_slh_dsa_file::<SlhDsaShake128sKeypair>("SLH-DSA-SHAKE-128s", "FIPS 205", &slh_keygen, PreHash::Shake128),
        ),
    ];

    let mut total = 0usize;
    for (fname, vf) in &files {
        let json = serde_json::to_string_pretty(vf).expect("serialize vector file");
        let path = out_dir.join(fname);
        fs::write(&path, format!("{json}\n")).expect("write vector file");
        println!("{fname:28} {:3} vectors", vf.vectors.len());
        total += vf.vectors.len();
    }
    println!("TOTAL: {total} vectors across {} files", files.len());
}
