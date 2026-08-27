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

console.log(`\n=== Results: ${passed} passed, ${failed} failed ===\n`);
if (failed > 0) process.exit(1);
