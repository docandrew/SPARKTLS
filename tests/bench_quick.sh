#!/bin/bash
# Quick handshake + x509 benchmark: SPARKTLS vs OpenSSL
set +e  # s_time returns 1 with self-signed certs
DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$DIR/.."
CERT="${BENCH_CERT:-$REPO/tests/certs/server.crt}"
KEY="${BENCH_KEY:-$REPO/tests/certs/server.key}"
SECS=${1:-3}

mkdir -p "$(dirname "$CERT")"
if [ ! -f "$CERT" ]; then
    openssl genpkey -algorithm ED25519 -out "$KEY" 2>/dev/null
    openssl req -new -x509 -key "$KEY" -out "$CERT" -days 365 -subj "/CN=localhost" 2>/dev/null
fi

pkill -f tls_web_epoll 2>/dev/null || true
pkill -f "openssl s_server" 2>/dev/null || true
sleep 0.5

mkdir -p /tmp/sparktls_bench
echo "OK" > /tmp/sparktls_bench/index.html

echo "=== Handshake benchmark (${SECS}s each) ==="
echo ""

# SPARKTLS
"$REPO/bin/examples/tls_web_epoll" "$CERT" "$KEY" /tmp/sparktls_bench >/dev/null 2>&1 &
PID=$!; sleep 0.5
openssl s_time -connect localhost:8443 -new -time $SECS > /tmp/bench_spark.txt 2>&1 &
wait $!
echo -n "SPARKTLS:  "; tail -1 /tmp/bench_spark.txt
kill $PID 2>/dev/null; wait $PID 2>/dev/null; sleep 0.5

# OpenSSL
openssl s_server -key "$KEY" -cert "$CERT" -accept 8444 -tls1_3 -quiet >/dev/null 2>&1 &
PID=$!; sleep 0.5
openssl s_time -connect localhost:8444 -new -time $SECS > /tmp/bench_ossl.txt 2>&1 &
wait $!
echo -n "OpenSSL:   "; tail -1 /tmp/bench_ossl.txt
kill $PID 2>/dev/null; wait $PID 2>/dev/null

echo ""
echo "=== x509 validation (5s each) ==="
echo ""

END=$(($(date +%s) + 5)); C=0
while [ $(date +%s) -lt $END ]; do
    "$REPO/bin/tests/x509_validate" "$CERT" "$CERT" --hostname localhost >/dev/null 2>&1 || true
    C=$((C+1))
done
echo "SPARKTLS:  $C validations in 5s ($((C/5))/sec)"

END=$(($(date +%s) + 5)); C=0
while [ $(date +%s) -lt $END ]; do
    openssl verify -CAfile "$CERT" "$CERT" >/dev/null 2>&1 || true
    C=$((C+1))
done
echo "OpenSSL:   $C validations in 5s ($((C/5))/sec)"
