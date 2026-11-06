# Secure Inline Communication Channel

A Linux prototype of a secure inline channel between two hosts, written in C:

```
PC1  ->  Device1  ->  Device2  ->  PC2
 plain TCP   encrypt     decrypt    plain TCP
```

Device1 and Device2 intercept selected TCP/IPv4 packets (Netfilter NFQUEUE). They first
establish a session key with an X25519 Diffie-Hellman handshake, then protect every TCP
payload with AES-256-GCM. IP and TCP headers are kept, the GCM tag is appended to the
encrypted payload, and no UDP encapsulation or custom header is used.

Linux network namespaces, veth and NFQUEUE need a Linux kernel. On macOS, run everything
inside a Linux VM (see "Setup").

## Implementation status

| Component                                              | Status      |
|--------------------------------------------------------|-------------|
| Four-namespace topology (`network/setup.sh`)           | Implemented |
| TCP file sender / receiver in C                        | Implemented |
| X25519 handshake between the devices (control channel) | Implemented |
| HKDF-SHA256 key derivation, per-direction keys         | Implemented |
| PSK-based key confirmation (anti-MITM)                 | Implemented |
| NFQUEUE interception, both directions                  | Implemented |
| AES-256-GCM on the TCP payload, tag appended           | Implemented |
| Checksum recalculation (IP + TCP)                      | Implemented |
| Unique nonce per packet + replay window                | Implemented |
| Unit tests (`make test`)                               | Implemented |
| End-to-end test (`make integration`)                   | Implemented |

## Repository layout

```
src/common/    crypto.c (X25519, HKDF, AES-GCM), packet.c (parse, checksums), channel.c (protect / unprotect)
src/device/    device.c - one program, used as Device1 (--role client) and Device2 (--role server)
src/sender/    TCP file sender
src/receiver/  TCP file receiver
network/       setup.sh / cleanup.sh - namespaces, veth, routes, iptables rules
tests/         test_channel.c (unit tests), run_integration.sh (end-to-end)
docs/          design.md - protocol, packet format, nonce design, MTU notes
```

## Setup (macOS + Ubuntu VM)

1. Install UTM (https://mac.getutm.app/) and create an Ubuntu 24.04 VM
   (ARM64 on Apple Silicon, x86_64 on Intel). 2+ CPU cores, 4 GB RAM, 25 GB disk.
2. Inside the VM:

```
sudo apt update
sudo apt install -y build-essential git libssl-dev libnetfilter-queue-dev \
  iproute2 iptables tcpdump ethtool iputils-ping
```

For the optional tamper test also: `sudo apt install linux-modules-extra-$(uname -r)` (netem).

## Build and test

```
make                # builds build/device, build/sender, build/receiver, build/test_channel
make test           # unit tests: no root, no network needed
sudo make integration            # full PC1 -> Device1 -> Device2 -> PC2 test
sudo tests/run_integration.sh --tamper   # also corrupts 2% of packets on the protected link
```

The integration test creates the topology, starts both devices, sends a ~900 KB text
file from PC1 to PC2 and checks:

1. the received file has the same SHA-256 as the sent file,
2. the plaintext marker is visible between PC1 and Device1 but **not** between Device1 and Device2,
3. Device1 encrypted exactly as many packets as Device2 decrypted, with no duplicate counters,
4. (tamper mode) corrupted packets are detected and dropped, and TCP still delivers the file.

Example output (from one run):

```
PASS: files identical
host side  (PC1 <-> Device1)     : 14441 lines with SECRET-LINE (expected > 0)
protected  (Device1 <-> Device2) : 0 lines with SECRET-LINE (expected 0)
[client] stats: encrypted=682 decrypted=0 auth_fail=0 replay=0 dropped=0
[server] stats: encrypted=0 decrypted=682 auth_fail=0 replay=0 dropped=0
ALL CHECKS PASSED
```

## Manual run

```
sudo network/setup.sh                    # topology + iptables rules (PORT=5000)

# terminal 1 (Device2)
sudo SC_PSK=secret ip netns exec device2 ./build/device --role server --ctrl-ip 10.0.12.2 -v
# terminal 2 (Device1)
sudo SC_PSK=secret ip netns exec device1 ./build/device --role client --ctrl-ip 10.0.12.2 -v
# terminal 3 (PC2)
sudo ip netns exec pc2 ./build/receiver 5000 receiver/received.txt
# terminal 4 (PC1)
printf 'hello from pc1\n' > sender/example.txt
sudo ip netns exec pc1 ./build/sender 10.0.2.2 5000 sender/example.txt

sudo ip netns exec device1 tcpdump -nn -A -i d1-d2     # protected link: unreadable payload
sudo network/cleanup.sh
```

## How the requirements are met

| Requirement                                       | Where                                         |
|---------------------------------------------------|-----------------------------------------------|
| PC1 -> Device1 -> Device2 -> PC2                  | `network/setup.sh`                            |
| Process selected TCP/IPv4 traffic                 | iptables rules + `parse_ipv4_tcp()`           |
| Secure session before protected transmission      | `handshake()` in `device.c`; queues bind after it, unbound queues drop |
| Diffie-Hellman shared session key                 | X25519 + HKDF in `crypto.c`                   |
| Encrypt only the TCP payload with AES-GCM         | `channel_protect()`                           |
| Keep IP/TCP headers, append tag, no UDP/header    | `channel.c`: ciphertext, tag, 8-byte counter  |
| Verify tag, decrypt, restore, recompute checksums | `channel_unprotect()`, `fix_checksums()`      |
| Unique nonce per packet in a session              | salt (4 B) + strictly increasing counter (8 B)|

See `docs/design.md` for the details.

## Design decisions to mention in the report

* **Nonce delivery.** The receiver needs the counter that forms the nonce. It is
  appended after the tag (8 bytes), so a protected packet is 24 bytes larger. If your
  instructor requires exactly +16 bytes, ask which nonce scheme they expect.
* **No TCP sequence translation is needed.** The encrypted packet is never terminated
  by a TCP stack, and Device2 restores the exact original packet.
* **MTU.** The kernel checks the forwarding MTU before the FORWARD hook: PCs use MTU 1400,
  devices 1500.
* **Authentication.** Plain DH is vulnerable to a man-in-the-middle; a PSK + HMAC key
  confirmation closes that gap.

## Limitations

IPv4/TCP only, IP fragments dropped, no rekeying (counter hard limit 2^48), one session
per run. Educational prototype; do not protect real traffic with it.

## Security

Do not commit private keys, pre-shared secrets, credentials or sensitive test data.
