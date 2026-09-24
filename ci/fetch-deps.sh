#!/usr/bin/env bash
# Clone the sibling crates that alire.toml pins by relative path.
#
# Why this exists: sparktls's alire.toml pins sparkx509, sparktlscrypto,
# sparkmlkem and sparkentropy with `path='../<name>'`; sparknacl comes
# from the Alire index. That is deliberate — it lets local
# development edit the crates side by side and have sparktls pick the changes
# up immediately. But CI checks out only sparktls, so those paths dangle and
# Alire falls back to the community index, where sparkx509 and sparktlscrypto
# are not published. The build then fails before anything is tested.
#
# `actions/checkout` cannot place a repo outside $GITHUB_WORKSPACE, so we
# clone the siblings ourselves into the parent directory.
#
# Idempotent: existing checkouts are left alone, so it is harmless to run on a
# developer machine that already has the siblings.
#
# Usage:  ci/fetch-deps.sh

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PARENT="$(dirname "$ROOT")"

# Commit-pinned for reproducibility. Bump deliberately, not by tracking a
# branch — a moving dependency makes CI failures impossible to bisect.
# Pins as of 2026-09-15. Override with the environment variable to test
# against a different revision (e.g. SPARKTLSCRYPTO_REF=master).
SPARKX509_URL="https://github.com/docandrew/sparkx509.git"
SPARKX509_REF="${SPARKX509_REF:-ba9c37170911a3ef564472187f83a6b38dac8fb2}"   # master 2026-09-15, PR #7 (empty NameConstraints subtrees)

SPARKTLSCRYPTO_URL="https://github.com/docandrew/sparktlscrypto.git"
SPARKTLSCRYPTO_REF="${SPARKTLSCRYPTO_REF:-b89c8bee8013498ac9008f92f4fd5480740e60df}"   # master 2026-09-23, SP 800-90A HMAC_DRBG with start-up self-test and CAVP KAT lane (PR #12)


# ML-KEM-768 for the X25519MLKEM768 key exchange (a library dependency).
SPARKMLKEM_URL="https://github.com/docandrew/sparkmlkem.git"
SPARKMLKEM_REF="${SPARKMLKEM_REF:-5fbd0c9ae7a498f4bd5350547ebaffba381156fa}"   # master 2026-09-21, stack-residue scanner gate (PR #1)

#  SPARK PIV client + Linux usbfs CCID transport; the examples project
#  (tls_yubikey_server, piv_signer) withs sparkpiv_linux.gpr. Library code
#  never depends on it.
SPARKPIV_URL="https://github.com/docandrew/sparkpiv.git"
SPARKPIV_REF="${SPARKPIV_REF:-bf2c38662aafa02ff6b358f43606038b23f82457}"   # main 2026-09-20, review fixes merged

# Needed by examples/ (pinned ../../sparkentropy). Without it the examples
# build fails and tls_fetch / tls_blocking_server never exist -- which the
# integration, protocol (tlsfuzzer), realworld and benchmark suites all need.
SPARKENTROPY_URL="https://github.com/docandrew/sparkentropy.git"
SPARKENTROPY_REF="${SPARKENTROPY_REF:-f707e61678576b4748c040d645b8ed427a28f8c8}"   # main 2026-09-23, intermittent/permanent health-test tiers, OSR accessors (PR #2)

clone_at() {
    local url="$1" ref="$2" dir="$3"
    if [[ -d "$PARENT/$dir" ]]; then
        echo "== $dir already present, leaving it alone"
        return
    fi
    echo "== cloning $dir @ ${ref:0:12}"
    git clone --quiet "$url" "$PARENT/$dir"
    git -C "$PARENT/$dir" checkout --quiet "$ref"
}

# Directory names must match the paths in alire.toml. All lowercase, which
# is also what `git clone` produces from the repo names -- no override needed.
clone_at "$SPARKX509_URL"      "$SPARKX509_REF"      "sparkx509"
clone_at "$SPARKTLSCRYPTO_URL" "$SPARKTLSCRYPTO_REF" "sparktlscrypto"
clone_at "$SPARKENTROPY_URL"   "$SPARKENTROPY_REF"   "sparkentropy"
clone_at "$SPARKMLKEM_URL"     "$SPARKMLKEM_REF"     "sparkmlkem"
clone_at "$SPARKPIV_URL"       "$SPARKPIV_REF"       "sparkpiv"

# sparknacl comes from the Alire index (sparknacl ^4.0.0 -> 4.0.1), not from a
# sibling clone: its git manifest pins gnatprove ^14.1.1, which no release of
# gnatprove 16 can satisfy, while the index release only requires gnat >= 14.2.1.
echo "== sibling crates ready under $PARENT"
ls -d "$PARENT"/sparkx509 "$PARENT"/sparktlscrypto "$PARENT"/sparkentropy "$PARENT"/sparkmlkem 2>/dev/null
