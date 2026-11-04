#!/bin/bash
# D2 Day 2 self-test for the new client modes (latency and flood).
# Usage:  cd sockets && ./check_new_modes.sh      (takes about 25 seconds)
cd "$(dirname "$0")" || exit 1
PASS=0; FAIL=0
check() { if [ "$2" = "yes" ]; then echo "  PASS  $1"; PASS=$((PASS+1)); else echo "  FAIL  $1"; FAIL=$((FAIL+1)); fi; }
field() { echo "$1" | tr ' ' '\n' | grep "^$2=" | head -n 1 | cut -d= -f2; }   # field "<line>" name

echo "== build =="
make clean >/dev/null; make 2>&1 | grep -E "warning|error" && check "build without warnings" no || check "build without warnings" yes

echo "== start server =="
./server > /tmp/m1_d2_server.log 2>&1 & SV=$!
python3 -c "
import socket, time
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', 9997)); s.listen(0); time.sleep(40)" & PY=$!
trap 'kill $SV $PY 2>/dev/null' EXIT
sleep 1

echo "== latency mode =="
OUT=$(./client 127.0.0.1 9000 latency 10 50)
SUM=$(echo "$OUT" | grep '^summary')
[ "$(echo "$OUT" | grep -c '^attempt=')" = "10" ] && check "prints one line per attempt" yes || check "prints one line per attempt" no
[ "$(field "$SUM" ok)" = "10" ] && check "10 of 10 logins ok" yes || check "10 of 10 logins ok" no
[ "$(field "$SUM" success_pct)" = "100.0" ] && check "success_pct is 100.0" yes || check "success_pct is 100.0" no
awk -v a="$(field "$SUM" avg_ms)" -v p="$(field "$SUM" p95_ms)" -v m="$(field "$SUM" max_ms)" 'BEGIN{exit !(a>0 && p>=a*0.5 && m>=p)}' \
  && check "avg, p95 and max look sensible" yes || check "avg, p95 and max look sensible" no

echo "== latency against a closed port =="
SUM=$(./client 127.0.0.1 9998 latency 2 0 | grep '^summary')
[ "$(field "$SUM" failed)" = "2" ] && [ "$(field "$SUM" ok)" = "0" ] && check "refused connections counted as failed" yes || check "refused connections counted as failed" no

echo "== latency against a server that never answers (takes ~2 s) =="
SUM=$(./client 127.0.0.1 9997 latency 2 0 | grep '^summary')
[ "$(field "$SUM" timeout)" = "2" ] && check "silent server counted as timeout, no hang" yes || check "silent server counted as timeout, no hang" no

echo "== flood mode =="
OUT=$(./client 127.0.0.1 9000 flood 20 3)
START=$(echo "$OUT" | grep '^flood start_epoch_ms' )
END=$(echo "$OUT" | grep '^flood attempted')
[ -n "$(field "$START" start_epoch_ms)" ] && check "prints start_epoch_ms" yes || check "prints start_epoch_ms" no
A=$(field "$END" attempted); C=$(field "$END" connected)
[ "$A" -ge 55 ] && [ "$A" -le 65 ] && check "about 60 attempts (20 per second for 3 s), got $A" yes || check "about 60 attempts (20 per second for 3 s), got $A" no
[ "$C" = "$A" ] && check "every connection succeeded" yes || check "every connection succeeded" no
[ "$(grep -c 'connect from' /tmp/m1_d2_server.log)" -ge 60 ] && check "server logged the flood connections" yes || check "server logged the flood connections" no

echo "== flood keeps its rate when connections hang (takes ~4 s) =="
END=$(./client 127.0.0.1 9997 flood 30 2 | grep '^flood attempted')
A=$(field "$END" attempted); T=$(field "$END" timeout)
[ "$A" -ge 55 ] && check "still attempted about 60 connections, got $A" yes || check "still attempted about 60 connections, got $A" no
[ "$T" -ge 50 ] && check "hung connections counted as timeout ($T)" yes || check "hung connections counted as timeout ($T)" no

echo "== usage messages =="
./client 127.0.0.1 9000 flood 20 2>&1 | grep -q usage && check "flood without seconds prints usage" yes || check "flood without seconds prints usage" no

echo; echo "$PASS passed, $FAIL failed"
[ "$FAIL" = "0" ]
