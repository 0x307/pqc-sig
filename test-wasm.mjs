// test-wasm.mjs — Functional test for all SLH-DSA WASM variants
import { readFile } from 'fs/promises';
import { fileURLToPath, pathToFileURL } from 'url';
import { dirname, join } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));

// Load the wasm-pack generated module
const distDir = join(__dirname, 'dist');

// We need to manually init since we're in Node.js, not a browser
const wasmBuffer = await readFile(join(distDir, 'pqc_sig_bg.wasm'));

// Import the JS glue — use pathToFileURL so Node.js ESM resolves the local file correctly
const { default: init, ...exports } = await import(pathToFileURL(join(distDir, 'pqc_sig.js')).href);

// Initialize with the wasm buffer using the new object-form API to avoid deprecation warning
await init({ module_or_path: wasmBuffer });

const encoder = new TextEncoder();
const message = encoder.encode("Hello, post-quantum world!");

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  ✅ ${name}`);
    passed++;
  } catch (e) {
    console.error(`  ❌ ${name}: ${e.message}`);
    failed++;
  }
}

function assert(condition, msg) {
  if (!condition) throw new Error(msg || 'assertion failed');
}

console.log('\n=== ML-DSA WASM Tests ===');

test('ML-DSA-44 keygen/sign/verify', () => {
  const kp = new exports.WasmMlDsa44Keypair();
  const pk = kp.public_key_bytes();
  assert(pk.length === 1312, `pk size ${pk.length} != 1312`);
  const sig = kp.sign(message);
  assert(sig.length === 2420, `sig size ${sig.length} != 2420`);
  assert(exports.ml_dsa_44_verify(pk, message, sig), 'verify failed');
});

test('ML-DSA-65 keygen/sign/verify', () => {
  const kp = new exports.WasmMlDsa65Keypair();
  const pk = kp.public_key_bytes();
  assert(pk.length === 1952, `pk size ${pk.length} != 1952`);
  const sig = kp.sign(message);
  assert(sig.length === 3309, `sig size ${sig.length} != 3309`);
  assert(exports.ml_dsa_65_verify(pk, message, sig), 'verify failed');
});

test('ML-DSA-87 keygen/sign/verify', () => {
  const kp = new exports.WasmMlDsa87Keypair();
  const pk = kp.public_key_bytes();
  assert(pk.length === 2592, `pk size ${pk.length} != 2592`);
  const sig = kp.sign(message);
  assert(sig.length === 4627, `sig size ${sig.length} != 4627`);
  assert(exports.ml_dsa_87_verify(pk, message, sig), 'verify failed');
});

console.log('\n=== SLH-DSA SHA2 WASM Tests ===');

test('SLH-DSA-SHA2-128s keygen/sign/verify', () => {
  const kp = new exports.WasmSlhDsaSha2_128sKeypair();
  const pk = kp.public_key_bytes();
  assert(pk.length === 32, `pk size ${pk.length} != 32`);
  const sig = kp.sign(message);
  assert(sig.length === 7856, `sig size ${sig.length} != 7856`);
  assert(exports.slh_dsa_sha2_128s_verify(pk, message, sig), 'verify failed');
});

test('SLH-DSA-SHA2-128f keygen/sign/verify', () => {
  const kp = new exports.WasmSlhDsaSha2_128fKeypair();
  const pk = kp.public_key_bytes();
  assert(pk.length === 32, `pk size ${pk.length} != 32`);
  const sig = kp.sign(message);
  assert(sig.length === 17088, `sig size ${sig.length} != 17088`);
  assert(exports.slh_dsa_sha2_128f_verify(pk, message, sig), 'verify failed');
});

test('SLH-DSA-SHA2-192s keygen/sign/verify', () => {
  const kp = new exports.WasmSlhDsaSha2_192sKeypair();
  const pk = kp.public_key_bytes();
  assert(pk.length === 48, `pk size ${pk.length} != 48`);
  const sig = kp.sign(message);
  assert(sig.length === 16224, `sig size ${sig.length} != 16224`);
  assert(exports.slh_dsa_sha2_192s_verify(pk, message, sig), 'verify failed');
});

test('SLH-DSA-SHA2-192f keygen/sign/verify', () => {
  const kp = new exports.WasmSlhDsaSha2_192fKeypair();
  const pk = kp.public_key_bytes();
  assert(pk.length === 48, `pk size ${pk.length} != 48`);
  const sig = kp.sign(message);
  assert(sig.length === 35664, `sig size ${sig.length} != 35664`);
  assert(exports.slh_dsa_sha2_192f_verify(pk, message, sig), 'verify failed');
});

test('SLH-DSA-SHA2-256s keygen/sign/verify', () => {
  const kp = new exports.WasmSlhDsaSha2_256sKeypair();
  const pk = kp.public_key_bytes();
  assert(pk.length === 64, `pk size ${pk.length} != 64`);
  const sig = kp.sign(message);
  assert(sig.length === 29792, `sig size ${sig.length} != 29792`);
  assert(exports.slh_dsa_sha2_256s_verify(pk, message, sig), 'verify failed');
});

test('SLH-DSA-SHA2-256f keygen/sign/verify', () => {
  const kp = new exports.WasmSlhDsaSha2_256fKeypair();
  const pk = kp.public_key_bytes();
  assert(pk.length === 64, `pk size ${pk.length} != 64`);
  const sig = kp.sign(message);
  assert(sig.length === 49856, `sig size ${sig.length} != 49856`);
  assert(exports.slh_dsa_sha2_256f_verify(pk, message, sig), 'verify failed');
});

console.log('\n=== SLH-DSA SHAKE WASM Tests ===');

test('SLH-DSA-SHAKE-128s keygen/sign/verify', () => {
  const kp = new exports.WasmSlhDsaShake128sKeypair();
  const pk = kp.public_key_bytes();
  assert(pk.length === 32, `pk size ${pk.length} != 32`);
  const sig = kp.sign(message);
  assert(sig.length === 7856, `sig size ${sig.length} != 7856`);
  assert(exports.slh_dsa_shake_128s_verify(pk, message, sig), 'verify failed');
});

test('SLH-DSA-SHAKE-128f keygen/sign/verify', () => {
  const kp = new exports.WasmSlhDsaShake128fKeypair();
  const pk = kp.public_key_bytes();
  assert(pk.length === 32, `pk size ${pk.length} != 32`);
  const sig = kp.sign(message);
  assert(sig.length === 17088, `sig size ${sig.length} != 17088`);
  assert(exports.slh_dsa_shake_128f_verify(pk, message, sig), 'verify failed');
});

test('SLH-DSA-SHAKE-192s keygen/sign/verify', () => {
  const kp = new exports.WasmSlhDsaShake192sKeypair();
  const pk = kp.public_key_bytes();
  assert(pk.length === 48, `pk size ${pk.length} != 48`);
  const sig = kp.sign(message);
  assert(sig.length === 16224, `sig size ${sig.length} != 16224`);
  assert(exports.slh_dsa_shake_192s_verify(pk, message, sig), 'verify failed');
});

test('SLH-DSA-SHAKE-192f keygen/sign/verify', () => {
  const kp = new exports.WasmSlhDsaShake192fKeypair();
  const pk = kp.public_key_bytes();
  assert(pk.length === 48, `pk size ${pk.length} != 48`);
  const sig = kp.sign(message);
  assert(sig.length === 35664, `sig size ${sig.length} != 35664`);
  assert(exports.slh_dsa_shake_192f_verify(pk, message, sig), 'verify failed');
});

test('SLH-DSA-SHAKE-256s keygen/sign/verify', () => {
  const kp = new exports.WasmSlhDsaShake256sKeypair();
  const pk = kp.public_key_bytes();
  assert(pk.length === 64, `pk size ${pk.length} != 64`);
  const sig = kp.sign(message);
  assert(sig.length === 29792, `sig size ${sig.length} != 29792`);
  assert(exports.slh_dsa_shake_256s_verify(pk, message, sig), 'verify failed');
});

test('SLH-DSA-SHAKE-256f keygen/sign/verify', () => {
  const kp = new exports.WasmSlhDsaShake256fKeypair();
  const pk = kp.public_key_bytes();
  assert(pk.length === 64, `pk size ${pk.length} != 64`);
  const sig = kp.sign(message);
  assert(sig.length === 49856, `sig size ${sig.length} != 49856`);
  assert(exports.slh_dsa_shake_256f_verify(pk, message, sig), 'verify failed');
});

console.log('\n=== Utility Functions ===');

test('pqc_sig_version returns string', () => {
  const v = exports.pqc_sig_version();
  assert(typeof v === 'string' && v.length > 0, `bad version: ${v}`);
  console.log(`    version = ${v}`);
});

test('public_key_size_for_algorithm', () => {
  assert(exports.public_key_size_for_algorithm('SLH-DSA-SHA2-192s') === 48);
  assert(exports.public_key_size_for_algorithm('SLH-DSA-SHAKE-256f') === 64);
});

test('signature_size_for_algorithm', () => {
  assert(exports.signature_size_for_algorithm('SLH-DSA-SHA2-192s') === 16224);
  assert(exports.signature_size_for_algorithm('SLH-DSA-SHAKE-256f') === 49856);
});

console.log('\n=== Domain separation (sign_ctx/verify_ctx) WASM Tests (0.4.0) ===');

test('ML-DSA-65 sign_ctx/verify_ctx round-trip', () => {
  const kp = new exports.WasmMlDsa65Keypair();
  const pk = kp.public_key_bytes();
  const agentCtx = encoder.encode('8gentz-agent-v1');
  const fabricCtx = encoder.encode('8gentz-fabric-v1');

  const sig = kp.sign_ctx(agentCtx, message);
  assert(sig.length === 3309, `sig size ${sig.length} != 3309`);

  // Correct context verifies without throwing.
  exports.ml_dsa_65_verify_ctx(pk, agentCtx, message, sig);

  // A signature made under one context must NOT verify under another --
  // verify_ctx throws (rejects) rather than returning false.
  let rejected = false;
  try {
    exports.ml_dsa_65_verify_ctx(pk, fabricCtx, message, sig);
  } catch (e) {
    rejected = true;
  }
  assert(rejected, 'cross-context verify_ctx must reject');

  // Plain (non-ctx) verify must also reject a context-bound signature.
  assert(!exports.ml_dsa_65_verify(pk, message, sig), 'plain verify must reject a ctx-bound signature');
});

test('SLH-DSA-SHA2-128s sign_ctx/verify_ctx round-trip', () => {
  const kp = new exports.WasmSlhDsaSha2_128sKeypair();
  const pk = kp.public_key_bytes();
  const ctx = encoder.encode('8gentz-agent-v1');

  const sig = kp.sign_ctx(ctx, message);
  assert(sig.length === 7856, `sig size ${sig.length} != 7856`);
  exports.slh_dsa_sha2_128s_verify_ctx(pk, ctx, message, sig);

  let rejected = false;
  try {
    exports.slh_dsa_sha2_128s_verify_ctx(pk, encoder.encode('other-ctx'), message, sig);
  } catch (e) {
    rejected = true;
  }
  assert(rejected, 'cross-context verify_ctx must reject');
});

console.log('\n=== Pre-hash signing (sign_prehash/verify_prehash) WASM Tests (0.4.0) ===');

test('ML-DSA-65 sign_prehash/verify_prehash round-trip (SHA-512)', () => {
  const kp = new exports.WasmMlDsa65Keypair();
  const pk = kp.public_key_bytes();
  const ctx = encoder.encode('8gentz-module-v1');

  // Stand-in 64-byte digest -- this test doesn't need a real hash, only a
  // correctly-sized one; SHA-512's collision strength (256 bits) satisfies
  // ML-DSA-65's 192-bit requirement.
  const digest = new Uint8Array(64).fill(0x11);

  const sig = kp.sign_prehash(ctx, 'SHA-512', digest);
  assert(sig.length === 3309, `sig size ${sig.length} != 3309`);

  // Correct digest verifies without throwing.
  exports.ml_dsa_65_verify_prehash(pk, ctx, 'SHA-512', digest, sig);

  // A tampered digest must be rejected.
  const tampered = digest.slice();
  tampered[0] ^= 0xff;
  let rejected = false;
  try {
    exports.ml_dsa_65_verify_prehash(pk, ctx, 'SHA-512', tampered, sig);
  } catch (e) {
    rejected = true;
  }
  assert(rejected, 'tampered digest must be rejected');

  // A pre-hash signature must NOT verify via plain verify() over the digest bytes
  // (the 0x01 domain byte structurally separates pre-hash from pure-mode signing).
  assert(!exports.ml_dsa_65_verify(pk, digest, sig), 'pre-hash signature must not verify via plain verify()');
});

test('ML-DSA-65 sign_prehash rejects SHA-256 as too weak', () => {
  const kp = new exports.WasmMlDsa65Keypair();
  const ctx = encoder.encode('8gentz-module-v1');
  const weakDigest = new Uint8Array(32).fill(0x22); // SHA-256 digest length

  let rejected = false;
  try {
    kp.sign_prehash(ctx, 'SHA-256', weakDigest);
  } catch (e) {
    rejected = true;
  }
  assert(rejected, 'SHA-256 (128-bit) must be rejected for ML-DSA-65 (192-bit requirement)');
});

console.log(`\n=== Results: ${passed} passed, ${failed} failed ===\n`);
if (failed > 0) process.exit(1);
