# build.ps1 — Canonical WASM build script for pqc-sig
#
# Usage (from workspace root or pqc-sig/):
#   powershell -ExecutionPolicy Bypass -File pqc-sig/build.ps1
#
# Or from inside pqc-sig/:
#   powershell -ExecutionPolicy Bypass -File build.ps1
#
# Produces pqc-sig/dist/ containing:
#   pqc_sig_bg.wasm        — compiled WebAssembly binary
#   pqc_sig.js             — JS glue module (ESM)
#   pqc_sig.d.ts           — TypeScript type definitions
#   pqc_sig_bg.wasm.d.ts   — WASM TypeScript definitions
#   pqc-sig.wit            — WIT interface file
#   package.json           — npm package manifest

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Resolve script directory so this works from any cwd
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "[build] Building pqc-sig WASM artifacts..." -ForegroundColor Cyan

# ── Step 1: wasm-pack build ───────────────────────────────────────────────────
# CRA-3: the standalone cdylib artifact is built from the sibling
# pqc-sig-wasm/ crate now, not this crate directly -- pqc-sig itself is
# rlib-only (an ordinary library, importable into other builds) and can no
# longer be built as a cdylib on its own. --out-dir is relative to
# pqc-sig-wasm/, so it points back up to this repo's dist/ to keep the
# existing output location.
Write-Host "[build] Running wasm-pack (pqc-sig-wasm/)..." -ForegroundColor Cyan
Push-Location (Join-Path $ScriptDir "pqc-sig-wasm")
try {
    wasm-pack build --target web --out-dir ..\dist --release -- --no-default-features
    if ($LASTEXITCODE -ne 0) {
        Write-Error "[build] wasm-pack failed with exit code $LASTEXITCODE"
        exit $LASTEXITCODE
    }
} finally {
    Pop-Location
}

# ── Step 2: Copy WIT interface file ──────────────────────────────────────────
Write-Host "[build] Copying WIT interface file..." -ForegroundColor Cyan
$WitSrc  = Join-Path $ScriptDir "wit\pqc-sig.wit"
$WitDest = Join-Path $ScriptDir "dist\pqc-sig.wit"
Copy-Item -Path $WitSrc -Destination $WitDest -Force

# ── Step 3: Write dist/package.json ──────────────────────────────────────────
Write-Host "[build] Writing dist/package.json..." -ForegroundColor Cyan
$PackageJson = @'
{
  "name": "pqc-sig",
  "version": "0.3.0",
  "description": "Post-quantum digital signatures: ML-DSA (FIPS 204), SLH-DSA (FIPS 205) — standalone WASM",
  "type": "module",
  "main": "./pqc_sig.js",
  "types": "./pqc_sig.d.ts",
  "files": [
    "pqc_sig_bg.wasm",
    "pqc_sig.js",
    "pqc_sig.d.ts",
    "pqc_sig_bg.wasm.d.ts",
    "pqc-sig.wit"
  ],
  "keywords": [
    "post-quantum",
    "signatures",
    "ml-dsa",
    "slh-dsa",
    "fips-204",
    "fips-205",
    "wasm",
    "cryptography"
  ],
  "license": "MIT OR Apache-2.0",
  "repository": {
    "type": "git",
    "url": "https://github.com/0x307/pqc-sig"
  },
  "exports": {
    ".": {
      "import": "./pqc_sig.js",
      "types": "./pqc_sig.d.ts"
    }
  }
}
'@
$PackageJsonPath = Join-Path $ScriptDir "dist\package.json"
Set-Content -Path $PackageJsonPath -Value $PackageJson -Encoding UTF8

# ── Step 4: Report ────────────────────────────────────────────────────────────
Write-Host "[build] Done. dist/ contents:" -ForegroundColor Green
Get-ChildItem (Join-Path $ScriptDir "dist") | Format-Table Name, Length -AutoSize
