#!/bin/bash
#  Write the integrity MACs into every executable under the given
#  directories that links the SPARKTLS module (tools/fips_inject
#  --if-present skips the rest). Builds the tool first if needed. Run it
#  after every link: an executable that has not been through it fails the
#  integrity self-test in RBG.Init and never starts a session.
#
#  Usage: inject_all.sh <dir-or-file>...
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TOOL="$ROOT/bin/tools/fips_inject"
if [ ! -x "$TOOL" ] || [ "$ROOT/tools/fips_inject/src/fips_inject.adb" -nt "$TOOL" ]; then
    ( cd "$ROOT" && eval "$(alr -n --no-tty printenv --unix)" \
      && gprbuild -q -P tools/fips_inject/fips_inject.gpr ) >/dev/null
fi
files=()
for arg in "$@"; do
    if [ -d "$arg" ]; then
        while IFS= read -r -d '' f; do files+=("$f"); done \
            < <(find "$arg" -maxdepth 1 -type f -perm -u+x -print0)
    elif [ -f "$arg" ]; then
        files+=("$arg")
    fi
done
[ ${#files[@]} -eq 0 ] && exit 0
out=$("$TOOL" --if-present "${files[@]}")
echo "fips_inject: $(printf '%s\n' "$out" | grep -c "integrity MACs written" || true) executables processed"
