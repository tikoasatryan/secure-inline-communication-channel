#!/usr/bin/env bash
# End-to-end test: PC1 -> Device1 -> Device2 -> PC2 with encryption in the middle.
#   sudo tests/run_integration.sh            normal run
#   sudo tests/run_integration.sh --tamper   also corrupt 2% of packets on the protected link
set -u
cd "$(dirname "$0")/.."
[ "$(id -u)" -eq 0 ] || { echo "Run as root (sudo)." >&2; exit 1; }
[ -x build/device ] || { echo "Run 'make' first." >&2; exit 1; }

PORT=5000
PSK="demo-shared-secret"
TAMPER=0; TAMPER_ACTIVE=0; [ "${1:-}" = "--tamper" ] && TAMPER=1
mkdir -p logs captures sender receiver

FAIL=0
step() { printf '\n== %s ==\n' "$*"; }

cleanup() {
    kill -INT "${TCP1:-}" "${TCP2:-}" 2>/dev/null
    kill -TERM "${D1:-}" "${D2:-}" 2>/dev/null
    sleep 0.5
}
trap cleanup EXIT

step "Create topology"
PORT=$PORT network/setup.sh || exit 1

step "Create test file (text, so plaintext is easy to spot in captures)"
if [ ! -f sender/testfile.txt ]; then
    for i in $(seq 1 15000); do echo "SECRET-LINE-$i the quick brown fox jumps over the lazy dog"; done \
        > sender/testfile.txt
fi
ls -l sender/testfile.txt | awk '{print $5 " bytes"}'
rm -f receiver/received.txt

step "Routing sanity check (ICMP is not selected, so it is not encrypted)"
ip netns exec pc1 ping -c1 -W2 10.0.2.2 >/dev/null && echo "pc1 -> pc2 reachable" || { echo "no connectivity"; exit 1; }

step "Start devices (handshake)"
SC_PSK="$PSK" ip netns exec device2 ./build/device --role server --ctrl-ip 10.0.12.2 -v > logs/device2.log 2>&1 &
D2=$!
SC_PSK="$PSK" ip netns exec device1 ./build/device --role client --ctrl-ip 10.0.12.2 -v > logs/device1.log 2>&1 &
D1=$!
for _ in $(seq 1 150); do
    grep -q READY logs/device1.log 2>/dev/null && grep -q READY logs/device2.log 2>/dev/null && break
    sleep 0.1
done
if grep -q READY logs/device1.log && grep -q READY logs/device2.log; then
    echo "both devices READY, handshake OK"
else
    echo "devices did not become ready:"; tail -5 logs/device1.log logs/device2.log; exit 1
fi

HAVE_TCPDUMP=0
if command -v tcpdump >/dev/null 2>&1; then
    HAVE_TCPDUMP=1
    ip netns exec device1 tcpdump -Z root -U -nn -i d1-p1 -w captures/host-side.pcap  tcp port $PORT >/dev/null 2>&1 &
    TCP1=$!
    ip netns exec device1 tcpdump -Z root -U -nn -i d1-d2 -w captures/protected-link.pcap tcp port $PORT >/dev/null 2>&1 &
    TCP2=$!
    sleep 1
fi

if [ $TAMPER -eq 1 ]; then
    step "Tamper mode: corrupt 2% of packets on the protected link"
    if ip netns exec device1 tc qdisc add dev d1-d2 root netem corrupt 2% 2>/dev/null; then
        TAMPER_ACTIVE=1
    else
        echo "SKIPPED: kernel has no netem (try: sudo apt install linux-modules-extra-\$(uname -r))"
    fi
fi

step "Transfer file PC1 -> PC2"
timeout 90 ip netns exec pc2 ./build/receiver $PORT receiver/received.txt > logs/receiver.log 2>&1 &
RPID=$!
sleep 1
timeout 90 ip netns exec pc1 ./build/sender 10.0.2.2 $PORT sender/testfile.txt
wait $RPID
cat logs/receiver.log

[ $TAMPER -eq 1 ] && ip netns exec device1 tc qdisc del dev d1-d2 root 2>/dev/null

step "Result: file integrity"
A=$(sha256sum < sender/testfile.txt); B=$(sha256sum < receiver/received.txt 2>/dev/null)
echo "sender  : $A"; echo "receiver: $B"
if [ "$A" = "$B" ]; then echo "PASS: files identical"; else echo "FAIL: files differ"; FAIL=1; fi

if [ $HAVE_TCPDUMP -eq 1 ]; then
    kill -INT $TCP1 $TCP2 2>/dev/null; sleep 1
    step "Result: confidentiality (packets containing the plaintext marker)"
    H=$(tcpdump -nn -A -r captures/host-side.pcap 2>/dev/null | grep -c "SECRET-LINE" || true)
    P=$(tcpdump -nn -A -r captures/protected-link.pcap 2>/dev/null | grep -c "SECRET-LINE" || true)
    echo "host side  (PC1 <-> Device1)     : $H lines with SECRET-LINE (expected > 0)"
    echo "protected  (Device1 <-> Device2) : $P lines with SECRET-LINE (expected 0)"
    [ "$H" -gt 0 ] && [ "$P" -eq 0 ] || { echo "FAIL: confidentiality check"; FAIL=1; }
else
    echo "(tcpdump not installed: skipping capture check)"
fi

step "Device statistics"
kill -TERM $D1 $D2 2>/dev/null; sleep 1
grep stats logs/device1.log logs/device2.log
echo "nonce check: counters sent by device1 -> $(grep -c '\[ENC\]' logs/device1.log) packets," \
     "$(grep '\[ENC\]' logs/device1.log | sed 's/.*ctr=\([0-9]*\).*/\1/' | sort -n | uniq -d | wc -l) duplicate counters (expected 0)"
if [ $TAMPER_ACTIVE -eq 1 ]; then
    AF=$(grep -c AUTH-FAIL logs/device2.log)
    echo "auth failures at device2 (expected > 0 in tamper mode): $AF"
    [ "$AF" -gt 0 ] || { echo "FAIL: corrupted packets were not detected"; FAIL=1; }
fi

echo; [ $FAIL -eq 0 ] && echo "ALL CHECKS PASSED" || echo "SOME CHECKS FAILED"
network/cleanup.sh >/dev/null
exit $FAIL
