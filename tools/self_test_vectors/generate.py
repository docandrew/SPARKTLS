#!/usr/bin/env python3
"""Generate src/sparktls-self_tests-vectors.ads: the known answers for the
FIPS 140-3 cryptographic algorithm self-tests (IG 10.3.A).

Usage: generate.py NIST_CACHE_DIR BORINGSSL_ACVP_TEST_DIR > src/sparktls-self_tests-vectors.ads

Every answer comes from outside this project's code:
  AES-GCM        BoringSSL's validated ACVP set (acvptool/test, BoGo pin)
  ML-KEM-768     NIST ACVP-Server sample sets (tests/acvp/run.sh pin); the
                 implicit-rejection key is SHAKE256(z || c') per FIPS 203
  SHA-512, HMAC, HKDF, TLS 1.2 PRF, TLS 1.3 HKDF-Expand-Label
                 Python's hashlib/hmac, on RFC 4231 / RFC 5869 inputs
  ECDSA, ECDH (P-256, P-384)
                 the affine curve arithmetic below, fixed scalars and nonce;
                 the curve constants are checked (G on the curve, [n]G = O)
  RSA-2048       PKCS#1 v1.5 encoding and modular exponentiation below on a
                 test key derived from a public seed string (no key file),
                 cross-checked with OpenSSL's signature
  Ed25519        RFC 8032 section 7.1 TEST 2, cross-checked with OpenSSL

Run it from the repository root; it needs openssl on PATH.
"""
import bz2, hashlib, hmac, json, os, re, subprocess, sys, tempfile

NIST, BSSL = sys.argv[1], sys.argv[2]
HERE = os.path.dirname(os.path.abspath(__file__))

def h(s):
    return bytes.fromhex(s)

# ---------------------------------------------------------------------------
# Hash-based
# ---------------------------------------------------------------------------
HMAC_KEY = b"Jefe"                                   # RFC 4231 test case 2
HMAC_MSG = b"what do ya want for nothing?"
HMAC256 = hmac.new(HMAC_KEY, HMAC_MSG, hashlib.sha256).digest()
HMAC384 = hmac.new(HMAC_KEY, HMAC_MSG, hashlib.sha384).digest()
assert HMAC256.hex().startswith("5bdcc146bf60754e")   # RFC 4231 printed value

SHA512_MSG = b"abc"
SHA512_MD = hashlib.sha512(SHA512_MSG).digest()

HKDF_IKM = bytes([0x0B] * 22)                         # RFC 5869 test case 1
HKDF_SALT = bytes(range(0x00, 0x0D))
HKDF_INFO = bytes(range(0xF0, 0xFA))
def hkdf_expand(prk, info, n, hf=hashlib.sha256):
    out, t, i = b"", b"", 1
    while len(out) < n:
        t = hmac.new(prk, t + info + bytes([i]), hf).digest(); out += t; i += 1
    return out[:n]
HKDF_OKM = hkdf_expand(hmac.new(HKDF_SALT, HKDF_IKM, hashlib.sha256).digest(), HKDF_INFO, 42)
assert HKDF_OKM.hex().startswith("3cb25f25faacd57a")  # RFC 5869 printed value

def p_hash(secret, seed, n, hf=hashlib.sha256):
    out, a = b"", seed
    while len(out) < n:
        a = hmac.new(secret, a, hf).digest()
        out += hmac.new(secret, a + seed, hf).digest()
    return out[:n]
TLS12_PMS = bytes((i * 7 + 3) & 0xFF for i in range(48))
TLS12_HASH = hashlib.sha256(b"ClientHello..ClientKeyExchange").digest()
TLS12_MS = p_hash(TLS12_PMS, b"extended master secret" + TLS12_HASH, 48)

TLS13_SECRET = hashlib.sha256(b"sparktls TLS 1.3 KDF self-test").digest()
TLS13_CTX = hashlib.sha256(b"").digest()
def expand_label(secret, label, ctx, n):
    full = b"tls13 " + label
    info = n.to_bytes(2, "big") + bytes([len(full)]) + full + bytes([len(ctx)]) + ctx
    return hkdf_expand(secret, info, n)
TLS13_OUT = expand_label(TLS13_SECRET, b"derived", TLS13_CTX, 32)

# ---------------------------------------------------------------------------
# Elliptic curves (affine, Python integers; only public test scalars)
# ---------------------------------------------------------------------------
CURVES = {
    "P256": dict(
        p=2**256 - 2**224 + 2**192 + 2**96 - 1,
        b=0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
        gx=0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
        gy=0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
        n=0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551, size=32,
        hf=hashlib.sha256),
    "P384": dict(
        p=2**384 - 2**128 - 2**96 + 2**32 - 1,
        b=0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF,
        gx=0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7,
        gy=0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F,
        n=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973, size=48,
        hf=hashlib.sha384),
}

def ec_add(c, P, Q):
    p = c["p"]
    if P is None: return Q
    if Q is None: return P
    if P[0] == Q[0] and (P[1] + Q[1]) % p == 0: return None
    if P == Q: l = (3 * P[0] * P[0] - 3) * pow(2 * P[1], -1, p) % p
    else:      l = (Q[1] - P[1]) * pow(Q[0] - P[0], -1, p) % p
    x = (l * l - P[0] - Q[0]) % p
    return (x, (l * (P[0] - x) - P[1]) % p)

def ec_mul(c, k, P):
    R = None
    while k:
        if k & 1: R = ec_add(c, R, P)
        P = ec_add(c, P, P); k >>= 1
    return R

def be(x, n):
    return x.to_bytes(n, "big")

EC = {}
for name, c in CURVES.items():
    G = (c["gx"], c["gy"])
    assert (G[1] ** 2 - (G[0] ** 3 - 3 * G[0] + c["b"])) % c["p"] == 0, name + ": G not on curve"
    assert ec_mul(c, c["n"], G) is None, name + ": [n]G is not the identity"
    size, n = c["size"], c["n"]
    d = int.from_bytes(hashlib.sha512(b"sparktls ECDSA key " + name.encode()).digest(), "big") % n
    k = int.from_bytes(hashlib.sha512(b"sparktls ECDSA nonce " + name.encode()).digest(), "big") % n
    Q = ec_mul(c, d, G)
    hsh = c["hf"](b"sparktls ECDSA self-test message").digest()
    e = int.from_bytes(hsh, "big")
    r = ec_mul(c, k, G)[0] % n
    s = pow(k, -1, n) * (e + r * d) % n
    w = pow(s, -1, n)
    assert ec_add(c, ec_mul(c, e * w % n, G), ec_mul(c, r * w % n, Q))[0] % n == r
    a = int.from_bytes(hashlib.sha512(b"sparktls ECDH local " + name.encode()).digest(), "big") % n
    bb = int.from_bytes(hashlib.sha512(b"sparktls ECDH peer " + name.encode()).digest(), "big") % n
    peer = ec_mul(c, bb, G)
    z = ec_mul(c, a, peer)[0]
    assert z == ec_mul(c, bb, ec_mul(c, a, G))[0]
    EC[name] = dict(D=be(d, size), K=be(k, size), Qx=be(Q[0], size), Qy=be(Q[1], size),
                    Hash=hsh, R=be(r, size), S=be(s, size),
                    ECDH_SK=be(a, size), ECDH_Peer=b"\x04" + be(peer[0], size) + be(peer[1], size),
                    ECDH_Z=be(z, size))

# ---------------------------------------------------------------------------
# RSA-2048 PKCS#1 v1.5, SHA-256
# ---------------------------------------------------------------------------
#  A publicly known test key, derived deterministically from the seed string
#  below so that no key file exists anywhere: anyone can rerun this and get
#  the same key. It signs nothing but this known answer, and its private
#  half protects nothing. Primes: SHA-512 counter-mode output from the seed,
#  top two bits and the low bit set, Miller-Rabin with 64 bases from the same
#  stream, e = 65537.
import math
RSA_SEED = b"sparktls RSA-2048 self-test key -- public, protects nothing"
def _stream(label):
    i = 0
    while True:
        yield hashlib.sha512(RSA_SEED + label + i.to_bytes(4, "big")).digest(); i += 1
def _prime(label, bits=1024):
    s = _stream(label)
    while True:
        c = int.from_bytes(next(s) + next(s), "big") >> (1024 - bits)
        c |= (3 << (bits - 2)) | 1
        if any(c % q == 0 for q in (3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)):
            continue
        d_, r = c - 1, 0
        while d_ % 2 == 0: d_ //= 2; r += 1
        def witness(a):
            x = pow(a, d_, c)
            if x in (1, c - 1): return False
            for _ in range(r - 1):
                x = pow(x, 2, c)
                if x == c - 1: return False
            return True
        bases = [2 + int.from_bytes(next(s)[:16], "big") % (c - 3) for _ in range(64)]
        if not any(witness(a) for a in bases) and math.gcd(c - 1, 65537) == 1:
            return c
E = 65537
P, Qp = _prime(b" p"), _prime(b" q")
if P < Qp: P, Qp = Qp, P
N = P * Qp
D = pow(E, -1, (P - 1) * (Qp - 1) // math.gcd(P - 1, Qp - 1))
DP, DQ, QI = D % (P - 1), D % (Qp - 1), pow(Qp, -1, P)
assert N.bit_length() == 2048

def _der_int(x):
    b = x.to_bytes((x.bit_length() + 8) // 8 or 1, "big")
    return b"\x02" + _der_len(len(b)) + b
def _der_len(n):
    return bytes([n]) if n < 128 else bytes([0x80 | len(n.to_bytes((n.bit_length() + 7) // 8, "big"))]) + n.to_bytes((n.bit_length() + 7) // 8, "big")
def _pkcs1_pem():
    body = b"".join(_der_int(x) for x in (0, N, E, D, P, Qp, DP, DQ, QI))
    der = b"\x30" + _der_len(len(body)) + body
    import base64
    b64 = base64.encodebytes(der).decode().replace("\n", "")
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return "-----BEGIN RSA PRIVATE KEY-----\n" + "\n".join(lines) + "\n-----END RSA PRIVATE KEY-----\n"
RSA_MSG = b"sparktls RSA self-test message"
RSA_HASH = hashlib.sha256(RSA_MSG).digest()
DI = h("3031300d060960864801650304020105000420") + RSA_HASH
EM = b"\x00\x01" + b"\xff" * (256 - 3 - len(DI)) + b"\x00" + DI
RSA_SIG = be(pow(int.from_bytes(EM, "big"), D, N), 256)
#  Cross-check with OpenSSL, the key written only to a temporary file.
with tempfile.TemporaryDirectory() as t:
    key, msg = os.path.join(t, "k.pem"), os.path.join(t, "m")
    open(key, "w").write(_pkcs1_pem()); open(msg, "wb").write(RSA_MSG)
    ossl = subprocess.run(["openssl", "dgst", "-sha256", "-sign", key, msg],
                          capture_output=True, check=True).stdout
assert ossl == RSA_SIG, "RSA signature differs from OpenSSL's"

# ---------------------------------------------------------------------------
# Ed25519: RFC 8032 section 7.1, TEST 2
# ---------------------------------------------------------------------------
ED_SEED = h("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
ED_PK = h("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
ED_MSG = h("72")
ED_SIG = h("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
           "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00")
with tempfile.TemporaryDirectory() as t:
    der = h("302e020100300506032b657004220420") + ED_SEED
    open(os.path.join(t, "k.der"), "wb").write(der)
    open(os.path.join(t, "m"), "wb").write(ED_MSG)
    sig = subprocess.run(["openssl", "pkeyutl", "-sign", "-rawin", "-keyform", "DER",
                          "-inkey", os.path.join(t, "k.der"), "-in", os.path.join(t, "m")],
                         capture_output=True, check=True).stdout
assert sig == ED_SIG, "Ed25519 signature differs from OpenSSL's"

# ---------------------------------------------------------------------------
# AES-GCM from BoringSSL's validated ACVP set
# ---------------------------------------------------------------------------
def load_bz2(path):
    raw, dec, i, out = bz2.open(path).read().decode(), json.JSONDecoder(), 0, []
    while i < len(raw):
        while i < len(raw) and raw[i].isspace(): i += 1
        if i == len(raw): break
        try: v, i = dec.raw_decode(raw, i)
        except json.JSONDecodeError: break
        out += v if isinstance(v, list) else [v]
    return [x for x in out if "testGroups" in x]
vec = load_bz2(os.path.join(BSSL, "vectors", "ACVP-AES-GCM.bz2"))[0]
exp = load_bz2(os.path.join(BSSL, "expected", "ACVP-AES-GCM.bz2"))[0]
EXP = {(g["tgId"], t["tcId"]): t for g in exp["testGroups"] for t in g["tests"]}
GCM = {}
for g in vec["testGroups"]:
    if g["ivLen"] != 96 or g["tagLen"] != 128 or g["keyLen"] not in (128, 256):
        continue
    for t in g["tests"]:
        x = EXP[(g["tgId"], t["tcId"])]
        key = (g["direction"], g["keyLen"])
        #  A payload always; AAD for the encrypt cases (BoringSSL's set has no
        #  256-bit decrypt case with both).
        if key in GCM or not (t.get("pt") or t.get("ct")):
            continue
        if g["direction"] == "encrypt" and not t.get("aad"):
            continue
        if g["direction"] == "encrypt":
            GCM[key] = dict(Key=h(t["key"]), IV=h(t["iv"]), AAD=h(t["aad"]), PT=h(t["pt"]),
                            CT=h(x["ct"]), Tag=h(x["tag"]))
        elif x.get("testPassed", True) and "pt" in x:
            GCM[key] = dict(Key=h(t["key"]), IV=h(t["iv"]), AAD=h(t["aad"]), CT=h(t["ct"]),
                            Tag=h(t["tag"]), PT=h(x["pt"]))
#  BoringSSL's set has no passing 256-bit decrypt case with a payload; the
#  256-bit decrypt test opens the 256-bit encrypt vector, as BoringSSL's own
#  self-test does.
if ("decrypt", 256) not in GCM:
    GCM[("decrypt", 256)] = dict(GCM[("encrypt", 256)])
assert len(GCM) == 4, sorted(GCM)

# ---------------------------------------------------------------------------
# ML-KEM-768 from NIST's sample sets
# ---------------------------------------------------------------------------
def nist(folder):
    p = json.load(open(os.path.join(NIST, folder, "prompt.json")))
    e = json.load(open(os.path.join(NIST, folder, "expectedResults.json")))
    E = {(g["tgId"], t["tcId"]): t for g in e["testGroups"] for t in g["tests"]}
    return [(g, t, E[(g["tgId"], t["tcId"])]) for g in p["testGroups"] for t in g["tests"]]
kg = next((t, x) for g, t, x in nist("ML-KEM-keyGen-FIPS203") if g["parameterSet"] == "ML-KEM-768")
enc = next((t, x) for g, t, x in nist("ML-KEM-encapDecap-FIPS203")
           if g["parameterSet"] == "ML-KEM-768" and g["function"] == "encapsulation")
def rejection_key(dk, c):
    return hashlib.shake_256(dk[-32:] + c).digest(32)
dec = next((t, x) for g, t, x in nist("ML-KEM-encapDecap-FIPS203")
           if g["parameterSet"] == "ML-KEM-768" and g["function"] == "decapsulation"
           and h(x["k"]) != rejection_key(h(t["dk"]), h(t["c"])))   # a valid ciphertext
DEC_DK, DEC_C = h(dec[0]["dk"]), h(dec[0]["c"])
BAD_C = bytes([DEC_C[0] ^ 1]) + DEC_C[1:]
MLKEM = dict(
    KG_D=h(kg[0]["d"]), KG_Z=h(kg[0]["z"]),
    KG_EK_SHA256=hashlib.sha256(h(kg[1]["ek"])).digest(),
    KG_DK_SHA256=hashlib.sha256(h(kg[1]["dk"])).digest(),
    Enc_EK=h(enc[0]["ek"]), Enc_M=h(enc[0]["m"]), Enc_K=h(enc[1]["k"]),
    Enc_C_SHA256=hashlib.sha256(h(enc[1]["c"])).digest(),
    Dec_DK=DEC_DK, Dec_C=DEC_C, Dec_K=h(dec[1]["k"]),
    Reject_K=rejection_key(DEC_DK, BAD_C))

# ---------------------------------------------------------------------------
# Ada output
# ---------------------------------------------------------------------------
consts = [
    ("HMAC_Key", HMAC_KEY), ("HMAC_Msg", HMAC_MSG), ("HMAC_SHA256", HMAC256), ("HMAC_SHA384", HMAC384),
    ("SHA512_Msg", SHA512_MSG), ("SHA512_MD", SHA512_MD),
    ("HKDF_IKM", HKDF_IKM), ("HKDF_Salt", HKDF_SALT), ("HKDF_Info", HKDF_INFO), ("HKDF_OKM", HKDF_OKM),
    ("TLS12_PMS", TLS12_PMS), ("TLS12_Session_Hash", TLS12_HASH), ("TLS12_Master", TLS12_MS),
    ("TLS13_Secret", TLS13_SECRET), ("TLS13_Context", TLS13_CTX), ("TLS13_Derived", TLS13_OUT),
]
for (d, bits), v in sorted(GCM.items()):
    pre = "GCM%d_%s_" % (bits, "Enc" if d == "encrypt" else "Dec")
    consts += [(pre + k, v[k]) for k in ("Key", "IV", "AAD", "PT", "CT", "Tag")]
for name in ("P256", "P384"):
    consts += [(name + "_" + k, v) for k, v in EC[name].items()]
consts += [("RSA_N", be(N, 256)), ("RSA_D", be(D, 256)), ("RSA_P", be(P, 128)), ("RSA_Q", be(Qp, 128)),
           ("RSA_DP", be(DP, 128)), ("RSA_DQ", be(DQ, 128)), ("RSA_QInv", be(QI, 128)),
           ("RSA_Hash", RSA_HASH), ("RSA_Sig", RSA_SIG)]
consts += [("Ed25519_Seed", ED_SEED), ("Ed25519_PK", ED_PK), ("Ed25519_Msg", ED_MSG), ("Ed25519_Sig", ED_SIG)]
consts += [("MLKEM_" + k, v) for k, v in MLKEM.items()]

def agg(b):
    items = ["16#%02X#" % x for x in b]
    lines = [", ".join(items[i:i + 12]) for i in range(0, len(items), 12)]
    return "(" + (",\n       ".join(lines) if len(b) > 1 else "0 => " + items[0]) + ")"

out = ["--  GENERATED by tools/self_test_vectors/generate.py -- do not edit.",
       "--  Known answers for the FIPS 140-3 algorithm self-tests (SPARKTLS.Self_Tests);",
       "--  see the generator for the source of every value.",
       "--",
       "--  Every key here (ECDSA, ECDH, RSA, Ed25519, ML-KEM) is a published test",
       "--  value: from an RFC or NIST sample, or derived by the generator from a",
       "--  fixed public string. They exist only to be checked against; none",
       "--  protects anything, and the library never uses them outside the",
       "--  self-tests.",
       "with SPARKNaCl; use SPARKNaCl;",
       "",
       "package SPARKTLS.Self_Tests.Vectors",
       "  with SPARK_Mode => On",
       "is",
       "   RSA_E : constant := %d;" % E, ""]
for name, v in consts:
    out.append("   %s : constant Byte_Seq (0 .. %d);" % (name, len(v) - 1))
out += ["", "private", "   --  The data is hidden from client proofs: they see each constant's",
        "   --  bounds, which is all the self-tests' preconditions need.",
        "   pragma Annotate (GNATprove, Hide_Info, \"Private_Part\");", ""]
for name, v in consts:
    out.append("   %s : constant Byte_Seq (0 .. %d) :=\n      %s;" % (name, len(v) - 1, agg(v)))
out.append("")
out.append("end SPARKTLS.Self_Tests.Vectors;")
print("\n".join(out))
