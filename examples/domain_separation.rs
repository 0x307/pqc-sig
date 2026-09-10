//! Domain separation example — `sign_ctx`/`verify_ctx` (S-1).
//!
//! Demonstrates binding an ML-DSA-65 signature to a specific application/protocol via
//! the FIPS 204 context string, so a signature produced for one purpose (e.g. an
//! "agent" identity) cannot be replayed as valid for another (e.g. a "fabric" identity)
//! even though both used the same underlying key pair.
//!
//! Run with:
//! ```sh
//! cargo run --example domain_separation
//! ```

use pqc_sig::fips204::MlDsa65Keypair;
use rand::rngs::OsRng;

const AGENT_CTX: &[u8] = b"8gentz-agent-v1";
const FABRIC_CTX: &[u8] = b"8gentz-fabric-v1";

fn main() {
    // Generate a single ML-DSA-65 key pair shared by both "roles" in this example.
    let keypair = MlDsa65Keypair::generate(&mut OsRng).expect("keygen failed");
    let pk = keypair.public_key();

    let message = b"transfer 100 credits to account #42";

    // Sign the same message under two different domain-separation contexts.
    let agent_sig = keypair
        .sign_ctx(&mut OsRng, AGENT_CTX, message)
        .expect("agent sign failed");
    let fabric_sig = keypair
        .sign_ctx(&mut OsRng, FABRIC_CTX, message)
        .expect("fabric sign failed");

    println!(
        "message:            {:?}",
        core::str::from_utf8(message).unwrap()
    );
    println!(
        "agent ctx:          {:?}",
        core::str::from_utf8(AGENT_CTX).unwrap()
    );
    println!(
        "fabric ctx:         {:?}",
        core::str::from_utf8(FABRIC_CTX).unwrap()
    );
    println!("agent signature:    {} bytes", agent_sig.bytes.len());
    println!("fabric signature:   {} bytes", fabric_sig.bytes.len());

    // Each signature verifies under its own context.
    MlDsa65Keypair::verify_ctx(&pk, AGENT_CTX, message, &agent_sig)
        .expect("agent signature must verify under its own context");
    println!("[ok]   agent signature verifies under AGENT_CTX");

    MlDsa65Keypair::verify_ctx(&pk, FABRIC_CTX, message, &fabric_sig)
        .expect("fabric signature must verify under its own context");
    println!("[ok]   fabric signature verifies under FABRIC_CTX");

    // Cross-context verification MUST fail: the agent signature must not be replayable
    // as a valid fabric signature, and vice versa.
    let result = MlDsa65Keypair::verify_ctx(&pk, FABRIC_CTX, message, &agent_sig);
    assert!(
        result.is_err(),
        "agent signature must NOT verify under FABRIC_CTX"
    );
    println!(
        "[ok]   agent signature is REJECTED under FABRIC_CTX: {:?}",
        result.unwrap_err()
    );

    let result = MlDsa65Keypair::verify_ctx(&pk, AGENT_CTX, message, &fabric_sig);
    assert!(
        result.is_err(),
        "fabric signature must NOT verify under AGENT_CTX"
    );
    println!(
        "[ok]   fabric signature is REJECTED under AGENT_CTX: {:?}",
        result.unwrap_err()
    );

    // Plain (non-ctx) `verify` also rejects both context-bound signatures, since it is
    // equivalent to `verify_ctx(pk, &[], ..)` — the empty context — which differs from
    // both AGENT_CTX and FABRIC_CTX.
    let result = MlDsa65Keypair::verify(&pk, message, &agent_sig);
    assert!(
        result.is_err(),
        "context-bound signature must NOT verify with plain verify()"
    );
    println!(
        "[ok]   agent signature is REJECTED by plain verify(): {:?}",
        result.unwrap_err()
    );

    // Empty context is byte-identical to the plain, non-ctx API.
    let plain_sig = keypair
        .sign_ctx_deterministic(&[], message)
        .expect("plain-ctx sign failed");
    let legacy_sig = keypair
        .sign_deterministic(message)
        .expect("legacy sign failed");
    assert_eq!(
        plain_sig.bytes, legacy_sig.bytes,
        "empty ctx must match the legacy sign path"
    );
    MlDsa65Keypair::verify(&pk, message, &plain_sig)
        .expect("empty-ctx signature must verify via plain verify()");
    println!("[ok]   sign_ctx_deterministic(&[], msg) == sign_deterministic(msg), and both verify via verify()");

    println!("\nDomain separation demo completed successfully.");
}
