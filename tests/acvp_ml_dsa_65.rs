//! NIST ACVP vectors for ML-DSA-65: keyGen, sigGen and sigVer (SIG-01).
//!
//! The vectors are NIST's, trimmed to the ML-DSA-65 cases pqc-sig's public API can
//! run (`tests/vectors/acvp/`, made by `scripts/trim-acvp-ml-dsa-65.py`). Source,
//! commit and what was left out are in `tests/vectors/README.md`, "Full ACVP
//! ML-DSA-65", and in each file's header.
//!
//! - keyGen: `from_secret_key_bytes(seed)` must give NIST's public key.
//! - sigGen: NIST's signature must verify under NIST's public key. ACVP gives the
//!   signing key in expanded form, which pqc-sig can't load (it takes the 32-byte
//!   seed), so this checks that pqc-sig accepts NIST's signatures, not that it
//!   reproduces them.
//! - sigVer: pqc-sig's verdict must match NIST's `testPassed`, for valid signatures
//!   and for NIST's modified ones.
//!
//! Each test also asserts its exact case count, so an emptied or truncated file
//! fails, and runs a built-in control: one hex digit flipped in a case that should
//! pass must make that case fail.

use serde::Deserialize;
use sha2::Digest as _;
use sha3::digest::{ExtendableOutput, Update, XofReader};

use pqc_sig::prehash::PreHash;
use pqc_sig::{MlDsa65Keypair, SigAlgorithm, SigPublicKey, Signature};

#[derive(Deserialize)]
struct AcvpFile {
    mode: String,
    revision: String,
    #[serde(rename = "parameterSet")]
    parameter_set: String,
    commit: String,
    kept_cases: usize,
    #[serde(rename = "testGroups")]
    test_groups: Vec<Group>,
}

#[derive(Deserialize)]
struct Group {
    #[serde(rename = "tgId")]
    tg_id: u32,
    #[serde(rename = "signatureInterface")]
    signature_interface: Option<String>,
    #[serde(rename = "preHash")]
    pre_hash: Option<String>,
    tests: Vec<Case>,
}

#[derive(Deserialize, Clone)]
struct Case {
    #[serde(rename = "tcId")]
    tc_id: u32,
    seed: Option<String>,
    pk: String,
    message: Option<String>,
    context: Option<String>,
    #[serde(rename = "hashAlg")]
    hash_alg: Option<String>,
    signature: Option<String>,
    #[serde(rename = "testPassed")]
    test_passed: Option<bool>,
}

const KEYGEN: &str = include_str!("vectors/acvp/ml_dsa_65_keygen.json");
const SIGGEN: &str = include_str!("vectors/acvp/ml_dsa_65_siggen.json");
const SIGVER: &str = include_str!("vectors/acvp/ml_dsa_65_sigver.json");

/// Pinned upstream commit, so a regenerated file from another revision is noticed.
const ACVP_COMMIT: &str = "975de31eb83d87039ec88934fdc47d8c312b892d";

fn load(json: &str, mode: &str, expected_cases: usize) -> AcvpFile {
    let f: AcvpFile = serde_json::from_str(json).expect("ACVP vector file parses");
    assert_eq!(f.mode, mode);
    assert_eq!(f.revision, "FIPS204");
    assert_eq!(f.parameter_set, "ML-DSA-65");
    assert_eq!(f.commit, ACVP_COMMIT);
    let n: usize = f.test_groups.iter().map(|g| g.tests.len()).sum();
    assert_eq!(n, f.kept_cases, "{mode}: header kept_cases disagrees with the cases present");
    assert_eq!(n, expected_cases, "{mode}: case count changed");
    f
}

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap_or_else(|e| panic!("bad hex: {e}"))
}

/// Flip one hex digit (the last one) of `s` to a different value.
fn flip_last_digit(s: &str) -> String {
    let mut out = s.to_owned();
    let last = out.pop().expect("non-empty hex");
    out.push(if last == '0' { '1' } else { '0' });
    assert_ne!(out, s);
    out
}

/// ACVP `hashAlg` name to pqc-sig's PreHash, and the caller-side digest of `msg`
/// (pqc-sig never hashes for the caller). SHAKE-256 is used with a 64-byte output,
/// as FIPS 204 specifies for HashML-DSA.
fn prehash(name: &str, msg: &[u8]) -> (PreHash, Vec<u8>) {
    match name {
        "SHA2-384" => (PreHash::Sha384, sha2::Sha384::digest(msg).to_vec()),
        "SHA2-512" => (PreHash::Sha512, sha2::Sha512::digest(msg).to_vec()),
        "SHA3-384" => (PreHash::Sha3_384, sha3::Sha3_384::digest(msg).to_vec()),
        "SHA3-512" => (PreHash::Sha3_512, sha3::Sha3_512::digest(msg).to_vec()),
        "SHAKE-256" => {
            let mut h = sha3::Shake256::default();
            h.update(msg);
            let mut out = vec![0u8; 64];
            h.finalize_xof().read(&mut out);
            (PreHash::Shake256, out)
        }
        other => panic!("hashAlg {other} is not in the trimmed files; see the trim script"),
    }
}

fn keygen_ok(c: &Case) -> bool {
    let kp = MlDsa65Keypair::from_secret_key_bytes(&unhex(c.seed.as_deref().expect("seed")))
        .expect("32-byte seed loads");
    // Compare bytes, not strings: NIST's hex is upper case.
    kp.public_key().bytes == unhex(&c.pk)
}

/// pqc-sig's verdict on one sigGen/sigVer case: does it verify?
fn verifies(g: &Group, c: &Case) -> bool {
    assert_eq!(g.signature_interface.as_deref(), Some("external"), "tg {}", g.tg_id);
    let pk = SigPublicKey::new(SigAlgorithm::MlDsa65, unhex(&c.pk));
    let sig = Signature::new(SigAlgorithm::MlDsa65, unhex(c.signature.as_deref().expect("signature")));
    let msg = unhex(c.message.as_deref().expect("message"));
    let ctx = unhex(c.context.as_deref().expect("context"));
    let result = match g.pre_hash.as_deref() {
        Some("pure") => MlDsa65Keypair::verify_ctx(&pk, &ctx, &msg, &sig),
        Some("preHash") => {
            let (hash, digest) = prehash(c.hash_alg.as_deref().expect("hashAlg"), &msg);
            MlDsa65Keypair::verify_prehash(&pk, &ctx, hash, &digest, &sig)
        }
        other => panic!("tg {}: preHash {other:?} is not in the trimmed files", g.tg_id),
    };
    result.is_ok()
}

#[test]
fn acvp_ml_dsa_65_keygen() {
    let f = load(KEYGEN, "keyGen", 25);
    let mut first = None;
    for g in &f.test_groups {
        for c in &g.tests {
            assert!(keygen_ok(c), "keyGen tg {} tc {}: derived public key differs from NIST's", g.tg_id, c.tc_id);
            first.get_or_insert(c);
        }
    }
    // Control: one flipped hex digit in NIST's public key must not match.
    let mut bad = first.expect("at least one case").clone();
    bad.pk = flip_last_digit(&bad.pk);
    assert!(!keygen_ok(&bad), "control: a flipped public-key digit still matched");
}

#[test]
fn acvp_ml_dsa_65_siggen_signatures_verify() {
    let f = load(SIGGEN, "sigGen", 43);
    let mut first = None;
    for g in &f.test_groups {
        for c in &g.tests {
            assert!(verifies(g, c), "sigGen tg {} tc {}: NIST's signature did not verify", g.tg_id, c.tc_id);
            first.get_or_insert((g, c));
        }
    }
    let (g, c) = first.expect("at least one case");
    let mut bad = c.clone();
    bad.signature = Some(flip_last_digit(bad.signature.as_deref().unwrap()));
    assert!(!verifies(g, &bad), "control: a flipped signature digit still verified");
}

#[test]
fn acvp_ml_dsa_65_sigver() {
    let f = load(SIGVER, "sigVer", 21);
    let (mut accepted, mut rejected) = (0, 0);
    let mut first_valid = None;
    for g in &f.test_groups {
        for c in &g.tests {
            let expected = c.test_passed.expect("testPassed");
            assert_eq!(
                verifies(g, c),
                expected,
                "sigVer tg {} tc {}: pqc-sig's verdict differs from NIST's",
                g.tg_id,
                c.tc_id
            );
            if expected {
                accepted += 1;
                first_valid.get_or_insert((g, c));
            } else {
                rejected += 1;
            }
        }
    }
    assert_eq!((accepted, rejected), (4, 17), "sigVer: mix of valid and invalid cases changed");
    let (g, c) = first_valid.expect("at least one valid case");
    let mut bad = c.clone();
    bad.signature = Some(flip_last_digit(bad.signature.as_deref().unwrap()));
    assert!(!verifies(g, &bad), "control: a flipped signature digit still verified");
}
