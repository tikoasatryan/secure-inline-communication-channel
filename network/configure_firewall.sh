#!/usr/bin/env bash
set -euo pipefail

# Placeholder for the NFQUEUE rules in a later milestone.
# Do not install queue rules until the Device1/Device2 programs are ready:
# packets sent to an unhandled NFQUEUE can stall or be dropped.

echo "NFQUEUE rules are not configured yet."
echo "Implement and test the packet handlers before adding firewall queue rules."
