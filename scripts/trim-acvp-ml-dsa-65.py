#!/usr/bin/env python3
"""Trim NIST ACVP ML-DSA vector files to the ML-DSA-65 cases pqc-sig can run.

Usage:
    python -I scripts/trim-acvp-ml-dsa-65.py <acvp-download-dir> tests/vectors/acvp

<acvp-download-dir> holds the three upstream files at their ACVP-Server paths:
    ML-DSA-keyGen-FIPS204/internalProjection.json
    ML-DSA-sigGen-FIPS204/internalProjection.json
    ML-DSA-sigVer-FIPS204/internalProjection.json
downloaded from
    https://raw.githubusercontent.com/usnistgov/ACVP-Server/<COMMIT>/gen-val/json-files/<name>/internalProjection.json

What is kept, and why (see tests/vectors/README.md, "Full ACVP ML-DSA-65"):
- Only parameterSet "ML-DSA-65".
- Only test groups pqc-sig's public API can run: keyGen (seed -> pk), and the
  sigGen/sigVer groups with signatureInterface "external" (pure, or preHash with a
  hash pqc-sig accepts for ML-DSA-65). Internal-interface and external-mu groups,
  and preHash cases with other hashes, are counted in "omitted", not copied.
- Fields: the ones the tests read. Dropped: "sk" (the expanded FIPS 204 signing
  key; pqc-sig loads only the 32-byte seed, so it can't be used), "rnd" (signing
  randomness; pqc-sig's public signing doesn't take it), "deferred". Values are
  copied byte for byte; nothing is re-encoded.
"""

import hashlib
import json
import os
import sys

COMMIT = "975de31eb83d87039ec88934fdc47d8c312b892d"
URL = ("https://raw.githubusercontent.com/usnistgov/ACVP-Server/" + COMMIT +
       "/gen-val/json-files/{name}/internalProjection.json")
PARAM = "ML-DSA-65"
# Pre-hash functions pqc-sig accepts for ML-DSA-65: in its PreHash enum, with at
# least 192 bits of collision strength (PreHash::collision_strength_bits).
PREHASH_OK = {"SHA2-384", "SHA2-512", "SHA3-384", "SHA3-512", "SHAKE-256"}

FILES = {
    "keyGen": ("ML-DSA-keyGen-FIPS204", "ml_dsa_65_keygen.json", ["tcId", "seed", "pk"]),
    "sigGen": ("ML-DSA-sigGen-FIPS204", "ml_dsa_65_siggen.json",
               ["tcId", "pk", "message", "context", "hashAlg", "signature"]),
    "sigVer": ("ML-DSA-sigVer-FIPS204", "ml_dsa_65_sigver.json",
               ["tcId", "pk", "message", "context", "hashAlg", "signature", "testPassed", "reason"]),
}
GROUP_META = ["tgId", "testType", "deterministic", "signatureInterface", "preHash", "externalMu",
              "cornerCase"]


def why_omitted(mode, g, t):
    if mode == "keyGen":
        return None
    if g.get("signatureInterface") != "external":
        if g.get("externalMu"):
            return "internal interface with external mu: pqc-sig has no public mu entry point"
        return "internal interface (ML-DSA.Sign_internal / Verify_internal): not in pqc-sig's public API"
    if g.get("preHash") == "preHash" and t["hashAlg"] not in PREHASH_OK:
        return ("preHash with %s: not a pqc-sig PreHash for ML-DSA-65 (unsupported, or below "
                "192-bit collision strength)" % t["hashAlg"])
    return None


def main(src, out):
    os.makedirs(out, exist_ok=True)
    for mode, (name, out_name, fields) in FILES.items():
        path = os.path.join(src, name, "internalProjection.json")
        raw = open(path, "rb").read()
        j = json.loads(raw)
        assert j["mode"] == mode and j["revision"] == "FIPS204", (path, j["mode"], j["revision"])
        groups, omitted, total = [], {}, 0
        for g in j["testGroups"]:
            if g["parameterSet"] != PARAM:
                continue
            kept = []
            for t in g["tests"]:
                total += 1
                reason = why_omitted(mode, g, t)
                if reason:
                    key = (g["tgId"], reason)
                    omitted[key] = omitted.get(key, 0) + 1
                    continue
                kept.append({f: t[f] for f in fields})
            if kept:
                meta = {k: g[k] for k in GROUP_META if k in g}
                meta["tests"] = kept
                groups.append(meta)
        doc = {
            "source": "NIST ACVP-Server gen-val/json-files/%s/internalProjection.json" % name,
            "url": URL.format(name=name),
            "commit": COMMIT,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "algorithm": j["algorithm"],
            "mode": j["mode"],
            "revision": j["revision"],
            "vsId": j["vsId"],
            "parameterSet": PARAM,
            "trimmed": ("ML-DSA-65 cases only; groups pqc-sig's public API can't run are counted "
                        "in 'omitted'; fields kept: %s (dropped: sk, rnd, deferred). Values are "
                        "unmodified. Made by scripts/trim-acvp-ml-dsa-65.py." % ", ".join(fields)),
            "upstream_cases": total,
            "kept_cases": sum(len(g["tests"]) for g in groups),
            "omitted": [{"tgId": k[0], "reason": k[1], "cases": n}
                        for k, n in sorted(omitted.items())],
            "testGroups": groups,
        }
        with open(os.path.join(out, out_name), "w", encoding="utf-8", newline="\n") as f:
            json.dump(doc, f, indent=1)
            f.write("\n")
        print("%s: %d of %d ML-DSA-65 cases kept -> %s" % (mode, doc["kept_cases"], total, out_name))


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
