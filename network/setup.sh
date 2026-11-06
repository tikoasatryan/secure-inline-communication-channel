#!/usr/bin/env bash
set -euo pipefail

# Run inside Ubuntu as root: sudo ./network/setup.sh
# This script only creates namespaces/interfaces with these project-specific names.

for ns in pc1 device1 device2 pc2; do
    if ip netns list | awk '{print $1}' | grep -qx "$ns"; then
        echo "Namespace '$ns' already exists. Run network/cleanup.sh first." >&2
        exit 1
    fi
done

cleanup_on_error() {
    for ns in pc1 device1 device2 pc2; do
        ip netns del "$ns" 2>/dev/null || true
    done
}
trap cleanup_on_error ERR

for ns in pc1 device1 device2 pc2; do
    ip netns add "$ns"
    ip -n "$ns" link set lo up
done

ip link add veth-pc1 type veth peer name veth-d1-in
ip link add veth-d1-out type veth peer name veth-d2-in
ip link add veth-d2-out type veth peer name veth-pc2

ip link set veth-pc1 netns pc1
ip link set veth-d1-in netns device1
ip link set veth-d1-out netns device1
ip link set veth-d2-in netns device2
ip link set veth-d2-out netns device2
ip link set veth-pc2 netns pc2

ip -n pc1 addr add 10.0.1.2/24 dev veth-pc1
ip -n device1 addr add 10.0.1.1/24 dev veth-d1-in
ip -n device1 addr add 10.0.12.1/24 dev veth-d1-out
ip -n device2 addr add 10.0.12.2/24 dev veth-d2-in
ip -n device2 addr add 10.0.2.1/24 dev veth-d2-out
ip -n pc2 addr add 10.0.2.2/24 dev veth-pc2

for item in \
    "pc1 veth-pc1" \
    "device1 veth-d1-in" \
    "device1 veth-d1-out" \
    "device2 veth-d2-in" \
    "device2 veth-d2-out" \
    "pc2 veth-pc2"; do
    read -r ns iface <<< "$item"
    ip -n "$ns" link set "$iface" up
done

ip -n pc1 route add default via 10.0.1.1
ip -n device1 route add 10.0.2.0/24 via 10.0.12.2
ip -n device2 route add 10.0.1.0/24 via 10.0.12.1
ip -n pc2 route add default via 10.0.2.1

for ns in device1 device2; do
    ip netns exec "$ns" sysctl -w net.ipv4.ip_forward=1 >/dev/null
    ip netns exec "$ns" sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null
    ip netns exec "$ns" sysctl -w net.ipv4.conf.default.rp_filter=0 >/dev/null
done

echo "Topology created."
echo "PC1:     10.0.1.2"
echo "Device1: 10.0.1.1 / 10.0.12.1"
echo "Device2: 10.0.12.2 / 10.0.2.1"
echo "PC2:     10.0.2.2"
echo "Test with: ip netns exec pc1 ping -c 3 10.0.2.2"
