#!/bin/bash
# Bulk-throughput TLS bench: SPARKTLS vs OpenSSL.
#
# For each TLS 1.3 cipher suite, run the same payload-download
# benchmark (one full handshake, then -reuse for the rest).  This
# exposes the per-suite symmetric throughput so AES-NI's effect on
# AES-GCM is measurable independently of ChaCha20-Poly1305.
#
# Usage:
#   tests/bench_bulk.sh                # default: 1 MB payload, 5s
#   tests/bench_bulk.sh 5 16777216     # 5s, 16 MB payload
set +e

DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$DIR/.."
CERT="${BENCH_CERT:-$REPO/tests/certs/server.crt}"
KEY="${BENCH_KEY:-$REPO/tests/certs/server.key}"
SECS=${1:-5}
SIZE=${2:-1048576}   # 1 MB default

mkdir -p "$(dirname "$CERT")"
if [ ! -f "$CERT" ]; then
    openssl genpkey -algorithm ED25519 -out "$KEY" 2>/dev/null
    openssl req -new -x509 -key "$KEY" -out "$CERT" \
        -days 365 -subj "/CN=localhost" 2>/dev/null
fi

pkill -f tls_web_epoll 2>/dev/null || true
pkill -f "openssl s_server" 2>/dev/null || true
sleep 0.5

DATA=/tmp/sparktls_bench
mkdir -p "$DATA"
echo "OK" > "$DATA/index.html"
dd if=/dev/urandom of="$DATA/payload.bin" bs=1 count=$SIZE status=none

human_size() {
  if [ "$1" -ge 1048576 ]; then printf '%d MB' $(( $1 / 1048576 ))
  else printf '%d KB' $(( $1 / 1024 )); fi
}

#  All TLS 1.3 ciphersuites that both implementations support.
SUITES=(
  TLS_AES_128_GCM_SHA256
  TLS_AES_256_GCM_SHA384
  TLS_CHACHA20_POLY1305_SHA256
)

echo "=== Bulk-throughput benchmark ==="
echo "    Payload:  $(human_size $SIZE) per response"
echo "    Duration: ${SECS}s per (server, suite) cell"
echo "    Mode:     -reuse (single handshake, many reused-session GETs)"
echo ""

run_client() {
  local PORT=$1 SUITE=$2
  local OUT
  OUT=$(openssl s_time -connect "localhost:$PORT" -reuse \
                       -ciphersuites "$SUITE" \
                       -www /payload.bin -time "$SECS" 2>&1 | tail -3)
  local CONNS BYTES_PER
  CONNS=$(echo "$OUT" | awk '/real seconds/ {print $1}')
  BYTES_PER=$(echo "$OUT" | awk '/bytes read per connection/ {print $(NF-4)}')
  if [ -z "$CONNS" ] || [ -z "$BYTES_PER" ]; then
    echo "FAIL ($SUITE) raw output:" >&2
    echo "$OUT" | sed 's/^/    /' >&2
    echo "FAIL"
    return
  fi
  awk "BEGIN { printf \"%.1f\", $CONNS * $BYTES_PER / $SECS / 1048576 }"
}

# Header
printf '%-32s %12s %12s\n' "suite" "SPARKTLS" "OpenSSL"
printf '%-32s %12s %12s\n' "-----" "(MB/s)" "(MB/s)"

for SUITE in "${SUITES[@]}"; do
  # SPARKTLS
  "$REPO/bin/examples/tls_web_epoll" "$CERT" "$KEY" "$DATA" >/dev/null 2>&1 &
  SPK_PID=$!; sleep 0.5
  SPK_MBPS=$(run_client 8443 "$SUITE")
  kill $SPK_PID 2>/dev/null; wait $SPK_PID 2>/dev/null; sleep 0.3

  # OpenSSL
  ( cd "$DATA" && openssl s_server -key "$KEY" -cert "$CERT" \
         -accept 8444 -tls1_3 -ciphersuites "$SUITE" \
         -WWW -quiet >/dev/null 2>&1 ) &
  OSL_PID=$!; sleep 0.5
  OSL_MBPS=$(run_client 8444 "$SUITE")
  kill $OSL_PID 2>/dev/null; wait $OSL_PID 2>/dev/null
  #  Give the kernel time to release the listen socket between suites.
  pkill -f "openssl s_server" 2>/dev/null; sleep 1.0

  printf '%-32s %12s %12s\n' "$SUITE" "$SPK_MBPS" "$OSL_MBPS"
done
