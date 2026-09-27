#!/usr/bin/env python3
"""Offline ACVP lane: NIST and BoringSSL vector sets through acvptool.

Usage: acvp.py ACVPTOOL WRAPPER NIST_DIR BORINGSSL_TEST_DIR

Each vector set is cut down to the parameters this module implements (the
filters below play the part of an ACVP registration), handed to BoringSSL's
acvptool in offline mode (-json), which drives tests/acvp/acvp_wrapper over
stdin/stdout, and every answer is compared with the expected result for its
test case. Only deterministic tests are run: key and signature generation
need an independent verifier and are not covered here.

Sources:
  NIST_DIR/<folder>/{prompt,expectedResults}.json  -- NIST's published
      sample sets (usnistgov/ACVP-Server gen-val/json-files, pinned in run.sh)
  BORINGSSL_TEST_DIR/{vectors,expected}/<name>.bz2 -- the sets and validated
      answers BoringSSL ships with acvptool (same pinned checkout as BoGo)
"""
import bz2, json, os, subprocess, sys, tempfile

ACVPTOOL, WRAPPER, NIST_DIR, BSSL_DIR = sys.argv[1:5]

# ---------------------------------------------------------------------------
# Filters: which test groups this module implements. Anything else in a
# vector set (other curves, IV lengths, SHA-3, prediction resistance, ...) is
# dropped before acvptool sees it.
# ---------------------------------------------------------------------------
def aes_gcm(vs, g):
    return (g.get("ivGen") == "external" and g.get("ivLen") == 96
            and g.get("tagLen") == 128 and g.get("keyLen") in (128, 256))

def sha2(vs, g):
    # acvptool implements the standard Monte Carlo test only, and no
    # large-data (LDT) tests.
    if g.get("testType") == "LDT":
        return False
    return g.get("testType") != "MCT" or g.get("mctVersion", "standard") == "standard"

def byte_oriented(vs, g, t):
    # The module hashes whole bytes; ACVP's bit-oriented messages (a length
    # in bits that is not a multiple of 8) are outside it.
    return t.get("len", 0) % 8 == 0 and t.get("msgLen", 0) % 8 == 0

def hmac(vs, g):
    # Full-length MACs only: acvptool asks the wrapper for exactly the
    # group's MAC length, and TLS never truncates HMAC.
    full = {"HMAC-SHA2-256": 256, "HMAC-SHA2-384": 384}.get(vs.get("algorithm"))
    return g.get("macLen", full) == full

def hkdf(vs, g):
    # acvptool implements the uPartyInfo||vPartyInfo fixed-info layout only.
    hk = g.get("kdfConfiguration") or {}
    return (hk.get("hmacAlg") in ("SHA2-256", "SHA2-384")
            and hk.get("fixedInfoPattern") == "uPartyInfo||vPartyInfo"
            and hk.get("fixedInfoEncoding") == "concatenation")

def tls12(vs, g):
    return g.get("hashAlg") in ("SHA2-256", "SHA2-384")

def tls13(vs, g):
    return g.get("hmacAlg") in ("SHA2-256", "SHA2-384")

def drbg(vs, g):
    return g.get("mode") == "SHA2-256" and not g.get("predResistance") and not g.get("derFunc")

def kas_ecc(vs, g):
    return (g.get("domainParameterGenerationMode") in ("P-256", "P-384")
            and g.get("scheme") == "ephemeralUnified")

def mlkem(vs, g):
    return g.get("parameterSet") == "ML-KEM-768"

def ecdsa_sigver(vs, g):
    # The pairings TLS uses: the verifier takes a digest of the curve's size.
    return (vs.get("mode") == "sigVer"
            and (g.get("curve"), g.get("hashAlg")) in (("P-256", "SHA2-256"), ("P-384", "SHA2-384")))

def eddsa_sigver(vs, g):
    return vs.get("mode") == "sigVer" and g.get("curve") == "ED-25519" and not g.get("preHash")

HASH_BYTES = {"SHA2-256": 32, "SHA2-384": 48, "SHA2-512": 64}

def rsa_sigver(vs, g):
    # 32-bit public exponents, and PSS only with MGF1 and a salt the length
    # of the hash (RFC 8446 4.2.3), which is what the verifier implements.
    e = g.get("e") or "010001"
    return (vs.get("mode") == "sigVer" and g.get("modulo") in (2048, 3072, 4096)
            and g.get("hashAlg") in HASH_BYTES
            and int(e, 16) < 2 ** 32
            and (g.get("sigType") == "pkcs1v1.5"
                 or (g.get("sigType") == "pss" and g.get("maskFunction", "mgf1") == "mgf1"
                     and g.get("saltLen") == HASH_BYTES[g.get("hashAlg")])))

NIST = [
    ("ACVP-AES-GCM-1.0", aes_gcm),
    ("SHA2-256-1.0", sha2), ("SHA2-384-1.0", sha2), ("SHA2-512-1.0", sha2),
    # Revision 1.0: acvptool reads its field layout (2.0 renamed the fields).
    ("HMAC-SHA2-256-1.0", hmac), ("HMAC-SHA2-384-1.0", hmac),
    # NIST's HKDF samples all append L to the fixed info, which acvptool
    # does not implement; HKDF is covered by BoringSSL's KDA set and, through
    # extract and expand-label, by the TLS 1.3 KDF sets.
    ("TLS-v1.2-KDF-RFC7627", tls12), ("TLS-v1.3-KDF-RFC8446", tls13),
    ("hmacDRBG-SP800-90Ar1", drbg),
    ("ML-KEM-keyGen-FIPS203", mlkem), ("ML-KEM-encapDecap-FIPS203", mlkem),
    ("ECDSA-SigVer-FIPS186-5", ecdsa_sigver), ("EDDSA-SigVer-1.0", eddsa_sigver),
    ("RSA-SigVer-FIPS186-5", rsa_sigver),
]

BSSL = [
    ("ACVP-AES-GCM", aes_gcm), ("SHA2-256", sha2), ("SHA2-384", sha2), ("SHA2-512", sha2),
    ("HMAC-SHA2-256", hmac), ("HMAC-SHA2-384", hmac),
    ("KDA", hkdf), ("TLS12", tls12), ("TLS13", tls13), ("hmacDRBG", drbg), ("KAS-ECC-SSC", kas_ecc),
    ("ML-KEM", mlkem), ("ECDSA", ecdsa_sigver), ("EDDSA", eddsa_sigver), ("RSA", rsa_sigver),
]

# ---------------------------------------------------------------------------
def filtered(vs, keep):
    vs = dict(vs)
    groups = []
    for g in vs["testGroups"]:
        if keep(vs, g):
            g = dict(g)
            g["tests"] = [t for t in g.get("tests") or [] if byte_oriented(vs, g, t)]
            if g["tests"]:
                groups.append(g)
    vs["testGroups"] = groups
    return vs if groups else None

def load_all(raw):
    """Every JSON value in raw, arrays flattened: some of BoringSSL's
    expected files are several documents one after another."""
    dec, out, i, raw = json.JSONDecoder(), [], 0, raw.decode()
    while i < len(raw):
        while i < len(raw) and raw[i].isspace():
            i += 1
        if i == len(raw):
            break
        try:
            v, i = dec.raw_decode(raw, i)
        except json.JSONDecodeError:
            if out:
                break   # trailing text after the documents (KDA ends "EOF.")
            raise
        out.extend(v if isinstance(v, list) else [v])
    return out

def index(vs):
    """(tgId, tcId) -> test dict, for an expected-results vector set."""
    out = {}
    for g in vs.get("testGroups") or []:
        for t in g.get("tests") or []:
            out[(g.get("tgId"), t["tcId"])] = t
    return out

def same(a, b):
    if isinstance(a, str) and isinstance(b, str):
        return a.lower() == b.lower()
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(same(x, y) for x, y in zip(a, b))
    if isinstance(a, dict) and isinstance(b, dict):
        return all(k in b and same(v, b[k]) for k, v in a.items())
    return a == b

def run_set(label, vs, expected):
    """Run one filtered vector set; return (passed, failed)."""
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump([{"acvVersion": "1.0"}, vs], f)
        path = f.name
    try:
        p = subprocess.run([ACVPTOOL, "-wrapper", WRAPPER, "-json", path],
                           capture_output=True, text=True, timeout=1800)
    finally:
        os.unlink(path)
    if p.returncode != 0:
        print("  FAIL: %s: acvptool: %s" % (label, (p.stderr or p.stdout).strip().splitlines()[-1:]))
        return 0, sum(len(g["tests"]) for g in vs["testGroups"])
    got_sets = [e for e in json.loads(p.stdout) if "testGroups" in e]
    want = index(expected)
    passed = failed = 0
    for got in got_sets:
        for g in got["testGroups"]:
            for t in g["tests"]:
                e = want.get((g.get("tgId"), t["tcId"]))
                if e is None:
                    continue
                fields = {k: v for k, v in e.items() if k != "tcId"}
                if same(fields, t):
                    passed += 1
                else:
                    failed += 1
                    if failed <= 3:
                        bad = [k for k in fields if not same(fields[k], t.get(k))]
                        print("  FAIL: %s tg %s tc %s: %s" % (label, g.get("tgId"), t["tcId"], ", ".join(bad)))
    status = "PASS" if failed == 0 and passed > 0 else "FAIL"
    print("  %s: %-40s %5d passed %3d failed" % (status, label, passed, failed))
    return passed, failed

def main():
    total_p = total_f = 0
    for folder, keep in NIST:
        prompt = json.load(open(os.path.join(NIST_DIR, folder, "prompt.json")))
        expected = json.load(open(os.path.join(NIST_DIR, folder, "expectedResults.json")))
        vs = filtered(prompt, keep)
        if vs is None:
            print("  SKIP: NIST %s (nothing this module implements)" % folder)
            continue
        p, f = run_set("NIST " + folder, vs, expected)
        total_p += p; total_f += f
    for name, keep in BSSL:
        exp_path = os.path.join(BSSL_DIR, "expected", name + ".bz2")
        if not os.path.exists(exp_path):
            # BoringSSL publishes no answers for sets whose tests use keys
            # the module generates (ECDH, signature generation).
            print("  SKIP: BoringSSL %s (no expected results published)" % name)
            continue
        vec = load_all(bz2.open(os.path.join(BSSL_DIR, "vectors", name + ".bz2")).read())
        exp = load_all(bz2.open(exp_path).read())
        vec_sets = [e for e in vec if "testGroups" in e]
        exp_sets = [e for e in exp if "testGroups" in e]
        for i, (v, e) in enumerate(zip(vec_sets, exp_sets)):
            vs = filtered(v, keep)
            if vs is None:
                continue
            label = "BoringSSL %s%s" % (name, "/" + v["mode"] if "mode" in v else "")
            p, f = run_set(label, vs, e)
            total_p += p; total_f += f
    print("=== ACVP: %d passed, %d failed ===" % (total_p, total_f))
    sys.exit(0 if total_f == 0 and total_p > 0 else 1)

main()
