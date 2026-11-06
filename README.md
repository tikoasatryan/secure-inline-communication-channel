# Secure Inline Communication Channel

A Linux-based C networking project prototype for a protected inline path:

```text
PC1  ->  Device1  ->  Device2  ->  PC2
```

The repository is designed to be developed on macOS and executed inside a Linux VM. Linux network namespaces, veth interfaces and Netfilter/NFQUEUE require a Linux kernel; they cannot run natively on macOS.

## Current implementation status

This repository is a **starter implementation**, not a finished transparent inline encryptor.

| Component | Status |
|---|---|
| Four-namespace topology script | Implemented |
| TCP file sender and receiver in C | Implemented |
| X25519 shared-secret test | Implemented |
| HKDF-SHA256 key derivation | Implemented |
| AES-256-GCM encrypt/decrypt test | Implemented |
| NFQUEUE packet interception | Scaffold / next milestone |
| Transparent TCP sequence/retransmission handling | Not implemented |
| End-to-end inline integration | Not implemented |

Do not describe the packet interception or transparent encryption features as complete until they have been implemented and tested.

## Important design note

The assignment asks to append a 16-byte GCM tag to each encrypted TCP payload while preserving the original IP and TCP headers and forwarding packets directly. Adding bytes to a TCP segment changes TCP sequence-space. A correct transparent implementation must also handle TCP sequence/acknowledgment translation, retransmissions, segmentation/coalescing, MTU limits, and both traffic directions. Simply changing a packet's payload length and checksum will not produce a reliable transparent TCP connection.

The nonce must also be available to the receiver and must never repeat with the same AES-GCM key. The project documentation should state the nonce/framing design agreed with the instructor. X25519 alone does not authenticate peers; the handshake needs authentication (for example, a pre-shared-key-based transcript MAC or signatures).

## Repository layout

```text
network/       Linux namespace and veth setup/cleanup scripts
src/common/    cryptographic helpers
src/sender/    TCP file sender
src/receiver/  TCP file receiver
src/device1/   future NFQUEUE encryptor
src/device2/   future NFQUEUE decryptor
tests/         cryptographic and transfer tests
docs/          architecture and implementation notes
```

## macOS development setup

1. Install Git and a code editor such as VS Code on macOS.
2. Install UTM: https://mac.getutm.app/
3. Create an Ubuntu 24.04 ARM64 VM on Apple Silicon, or Ubuntu 24.04 x86_64 on an Intel Mac.
4. Give the VM at least 2 CPU cores, 4 GB RAM and 25 GB disk.
5. Boot Ubuntu and install the dependencies below.
6. Copy this repository into the VM (shared folder, `git clone`, or ZIP transfer).

The Linux VM is where all network namespace and NFQUEUE commands must run.

### Install dependencies on Ubuntu

```bash
sudo apt update
sudo apt install -y build-essential gcc make git \
  libssl-dev libnetfilter-queue-dev libmnl-dev \
  iproute2 iptables nftables tcpdump ethtool
```

## Build

From the repository root:

```bash
make
```

This builds:
- `build/sender`
- `build/receiver`
- `build/test_crypto`

## Run the basic TCP file-transfer test

Open two Ubuntu terminal windows.

Terminal 1 — start the receiver:

```bash
mkdir -p receiver
./build/receiver 9000 receiver/received.bin
```

Terminal 2 — send a file:

```bash
mkdir -p sender
printf 'Hello from the secure inline channel project\n' > sender/example.txt
./build/sender 127.0.0.1 9000 sender/example.txt
```

Compare the files:

```bash
cmp sender/example.txt receiver/received.bin
sha256sum sender/example.txt receiver/received.bin
```

The hashes should match.

## Run the cryptographic self-test

```bash
./build/test_crypto
```

The test generates two X25519 key pairs, derives a common secret on both sides, derives an AES key using HKDF-SHA256, and checks AES-256-GCM encryption/decryption plus rejection of a modified tag.

## Create the virtual network

Run only inside the Ubuntu VM:

```bash
sudo ./network/cleanup.sh
sudo ./network/setup.sh
```

Check the namespaces and interfaces:

```bash
sudo ip netns list
sudo ip netns exec pc1 ip addr
sudo ip netns exec device1 ip addr
sudo ip netns exec device2 ip addr
sudo ip netns exec pc2 ip addr
```

Test routed connectivity:

```bash
sudo ip netns exec pc1 ping -c 3 10.0.2.2
```

At this milestone, traffic is routed normally. It is **not yet encrypted**.

Remove the topology:

```bash
sudo ./network/cleanup.sh
```

## GitHub

Create an empty repository on GitHub, then from this directory:

```bash
git init
git add .
git commit -m "Add initial C networking project"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/secure-inline-communication-channel.git
git push -u origin main
```

Replace `YOUR_USERNAME` with your GitHub username.

## Planned milestones

1. Verify the Linux VM and four-namespace topology.
2. Verify the TCP file-transfer application.
3. Complete and test the X25519/HKDF/AES-GCM cryptographic module.
4. Agree on nonce/framing and TCP stream-handling design.
5. Implement authenticated Device1–Device2 handshake.
6. Implement NFQUEUE interception and packet processing.
7. Integrate both directions, retransmission handling, checksums and MTU tests.
8. Document results and capture test evidence.

## Security

This is an educational prototype. Do not use it to protect real production traffic. Do not commit private keys, pre-shared secrets, credentials, or sensitive test data.
