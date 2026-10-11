#!/bin/bash
# Member 1 self-test: runs everything on this machine, no Mininet needed.
# Usage:  cd sockets && ./local_test.sh      (takes about 20 seconds)
cd "$(dirname "$0")" || exit 1
PASS=0; FAIL=0
check() { if [ "$2" = "yes" ]; then echo "  PASS  $1"; PASS=$((PASS+1)); else echo "  FAIL  $1"; FAIL=$((FAIL+1)); fi; }

echo "== build =="
make clean >/dev/null; make 2>&1 | grep -E "warning|error" && check "build without warnings" no || check "build without warnings" yes

echo "== unit tests (detect.c) =="
make test 2>&1 | grep -q "all detect tests passed" && check "detector unit tests" yes || check "detector unit tests" no

echo "== start mock controller and server =="
./mock_controller > /tmp/m1_mock.log 2>&1 & MC=$!
./server > /tmp/m1_server.log 2>&1 & SV=$!
trap 'kill $MC $SV 2>/dev/null' EXIT
sleep 1

echo "== normal client =="
OUT=$(./client 127.0.0.1 9000 normal 2 200)
[ "$(echo "$OUT" | grep -c '<- OK')" = "2" ] && check "2 valid logins accepted" yes || check "2 valid logins accepted" no
echo "$OUT" | grep -q "ECHO hello" && check "ECHO works" yes || check "ECHO works" no

echo "== burst client =="
./client 127.0.0.1 9000 burst 10 20 | grep -q "opened 10" && check "burst opens 10 connections" yes || check "burst opens 10 connections" no

echo "== below threshold (4 bad logins) =="
./client 127.0.0.1 9000 badlogin 4 100 > /dev/null
sleep 1
grep -q "BLOCK" /tmp/m1_mock.log && check "4 failures do not trigger BLOCK" no || check "4 failures do not trigger BLOCK" yes

echo "   waiting 11 s so the old failures leave the 10 s window..."
sleep 11

echo "== threshold (5 bad logins) =="
./client 127.0.0.1 9000 badlogin 5 100 > /dev/null
sleep 1
grep -q "received: BLOCK 127.0.0.1 30" /tmp/m1_mock.log && check "5 failures send BLOCK 127.0.0.1 30" yes || check "5 failures send BLOCK 127.0.0.1 30" no
grep -q "controller replied: OK" /tmp/m1_server.log && check "server logs controller reply" yes || check "server logs controller reply" no

echo "== no repeat while blocked =="
./client 127.0.0.1 9000 badlogin 4 100 > /dev/null
sleep 1
[ "$(grep -c 'received: BLOCK' /tmp/m1_mock.log)" = "1" ] && check "no second BLOCK while blocked" yes || check "no second BLOCK while blocked" no

echo "== two clients at once =="
./client 127.0.0.1 9000 normal 3 100 > /tmp/m1_c1.log &
./client 127.0.0.1 9000 normal 3 100 > /tmp/m1_c2.log &
wait %3 %4 2>/dev/null; sleep 1
[ "$(grep -c '<- OK' /tmp/m1_c1.log)" = "3" ] && [ "$(grep -c '<- OK' /tmp/m1_c2.log)" = "3" ] && check "two concurrent clients both served" yes || check "two concurrent clients both served" no

echo "== controller down =="
kill $MC 2>/dev/null; sleep 1
./client 127.0.0.1 9000 normal 1 100 | grep -q "<- OK" && check "server still serves when controller is down" yes || check "server still serves when controller is down" no

echo; echo "$PASS passed, $FAIL failed"
[ "$FAIL" = "0" ]
