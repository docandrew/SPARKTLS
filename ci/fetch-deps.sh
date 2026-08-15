#!/usr/bin/env bash
# Clone the sibling crates that alire.toml pins by relative path.
#
# Why this exists: sparktls's alire.toml pins sparkx509, sparknacl and
# sparktlscrypto with `path='../<name>'`. That is deliberate — it lets local
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
SPARKX509_URL="https://github.com/docandrew/sparkx509.git"
SPARKX509_REF="${SPARKX509_REF:-c1dac96dea4d1569f9369690c0c662a91ee63161}"

SPARKTLSCRYPTO_URL="https://github.com/docandrew/sparktlscrypto.git"
SPARKTLSCRYPTO_REF="${SPARKTLSCRYPTO_REF:-2cbba6a6bb064d4a9f63cd9efbf029a7092b4aff}"

SPARKNACL_URL="https://github.com/rod-chapman/sparknacl.git"
SPARKNACL_REF="${SPARKNACL_REF:-49e3bddf092561ce2b74c134a35acff91a2da9a4}"

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

# Directory names must match the paths in alire.toml exactly, including case:
#   sparkx509 = { path='../sparkx509' }
#   sparknacl = { path='../sparknacl' }
#   sparktlscrypto = { path='../SPARKTLSCrypto' }
clone_at "$SPARKX509_URL"      "$SPARKX509_REF"      "sparkx509"
clone_at "$SPARKTLSCRYPTO_URL" "$SPARKTLSCRYPTO_REF" "SPARKTLSCrypto"
clone_at "$SPARKNACL_URL"      "$SPARKNACL_REF"      "sparknacl"

# --- sparknacl toolchain constraint -------------------------------------
# Committed sparknacl HEAD declares gnatprove = "^14.1.1" and gnat >= 14.2.1.
# Every crate here requires ^15.1.0 / ^15.2.1. Those ranges are disjoint, so
# `alr` reports "gnatprove(...) (direct,missed:conflict)" and refuses to
# resolve. The primary dev box only works because this edit sits unstaged in
# its working tree.
#
# TODO: remove this once the change is committed somewhere fetchable — fork to
# docandrew/sparknacl, commit, and point SPARKNACL_URL/REF at it. Carrying the
# fix as a sed here means every consumer has to know about it.
NACL_TOML="$PARENT/sparknacl/alire.toml"
if [[ -f "$NACL_TOML" ]] && grep -q '\^14\.1\.1' "$NACL_TOML"; then
    echo "== patching sparknacl toolchain constraints (see comment in $0)"
    sed -i 's/gnatprove = "\^14\.1\.1"/gnatprove = "^15.1.0"/' "$NACL_TOML"
    sed -i 's/gnat=">=14\.2\.1"/gnat = "^15.2.1"/'             "$NACL_TOML"
fi

echo "== sibling crates ready under $PARENT"
ls -d "$PARENT"/sparkx509 "$PARENT"/SPARKTLSCrypto "$PARENT"/sparknacl 2>/dev/null
