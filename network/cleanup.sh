#!/usr/bin/env bash
# Removes the four namespaces (their veth interfaces disappear with them).
[ "$(id -u)" -eq 0 ] || { echo "Run as root (sudo)." >&2; exit 1; }
pkill -x device 2>/dev/null || true
for ns in pc1 device1 device2 pc2; do
    ip netns del "$ns" 2>/dev/null || true
done
echo "cleanup done"
