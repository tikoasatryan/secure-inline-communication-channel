#!/usr/bin/env bash
# Builds:   pc1 --- device1 === device2 --- pc2
#
#   pc1     p1-d1  10.0.1.2/24   (MTU 1400)
#   device1 d1-p1  10.0.1.1/24   (MTU 1500)   <- host side
#   device1 d1-d2  10.0.12.1/24               <- protected link
#   device2 d2-d1  10.0.12.2/24               <- protected link
#   device2 d2-p2  10.0.2.1/24   (MTU 1500)   <- host side
#   pc2     p2-d2  10.0.2.2/24   (MTU 1400)
#
# MTU design: the PCs use MTU 1400, the devices use 1500 on every interface.
# A protected packet is 24 bytes bigger than the original (<= 1424). The kernel
# checks the forwarding MTU BEFORE the netfilter FORWARD hook, so Device2/Device1
# must be able to forward the still-encrypted packet through their host-side
# interface (1500) before the program shrinks it back to the original size.
set -euo pipefail
PORT="${PORT:-5000}"          # protected TCP port (source OR destination)

[ "$(id -u)" -eq 0 ] || { echo "Run as root (sudo)." >&2; exit 1; }
"$(dirname "$0")/cleanup.sh" >/dev/null

for ns in pc1 device1 device2 pc2; do
    ip netns add "$ns"
    ip -n "$ns" link set lo up
done

ip link add p1-d1 type veth peer name d1-p1
ip link add d1-d2 type veth peer name d2-d1
ip link add d2-p2 type veth peer name p2-d2
ip link set p1-d1 netns pc1;     ip link set d1-p1 netns device1
ip link set d1-d2 netns device1; ip link set d2-d1 netns device2
ip link set d2-p2 netns device2; ip link set p2-d2 netns pc2

cfg() { # ns dev addr mtu
    ip -n "$1" addr add "$3" dev "$2"
    ip -n "$1" link set "$2" mtu "$4" up
}
cfg pc1     p1-d1 10.0.1.2/24  1400
cfg device1 d1-p1 10.0.1.1/24  1500
cfg device1 d1-d2 10.0.12.1/24 1500
cfg device2 d2-d1 10.0.12.2/24 1500
cfg device2 d2-p2 10.0.2.1/24  1500
cfg pc2     p2-d2 10.0.2.2/24  1400

ip -n pc1 route add default via 10.0.1.1
ip -n pc2 route add default via 10.0.2.1
ip -n device1 route add 10.0.2.0/24 via 10.0.12.2
ip -n device2 route add 10.0.1.0/24 via 10.0.12.1

for d in device1 device2; do
    ip netns exec "$d" sysctl -qw net.ipv4.ip_forward=1
done

# Offloads must be off: otherwise the kernel hands us oversized / unchecksummed packets.
if command -v ethtool >/dev/null 2>&1; then
    for pair in pc1:p1-d1 device1:d1-p1 device1:d1-d2 device2:d2-d1 device2:d2-p2 pc2:p2-d2; do
        ip netns exec "${pair%%:*}" ethtool -K "${pair##*:}" \
            tx off rx off sg off tso off gso off gro off >/dev/null 2>&1 || true
    done
else
    echo "WARNING: ethtool not installed - install it (sudo apt install ethtool)" >&2
fi

# Selected traffic = TCP with source or destination port $PORT.
#   packets entering from the host side  -> queue 0 (encrypt)
#   packets entering from the peer side  -> queue 1 (decrypt)
# If the device program is not running, nothing is bound to the queues and the
# packets are DROPPED - so no plaintext can leak before the session exists.
rules() { # ns host-side-if peer-side-if
    ip netns exec "$1" iptables -F FORWARD
    ip netns exec "$1" iptables -A FORWARD -i "$2" -p tcp -m multiport --ports "$PORT" \
        -j NFQUEUE --queue-num 0
    ip netns exec "$1" iptables -A FORWARD -i "$3" -p tcp -m multiport --ports "$PORT" \
        -j NFQUEUE --queue-num 1
}
rules device1 d1-p1 d1-d2
rules device2 d2-p2 d2-d1

echo "topology ready (protected TCP port: $PORT)"
