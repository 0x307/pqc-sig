//! See Cargo.toml for what this fixture proves and why it must live outside
//! `tests/*.rs`. Referencing an item (not just listing the dependency) makes
//! sure `pqc-sig` is genuinely compiled and linked into this crate's cdylib
//! artifact, not just resolved.

pub use pqc_sig::SigAlgorithm;

pub fn touch() -> SigAlgorithm {
    SigAlgorithm::MlDsa65
}
