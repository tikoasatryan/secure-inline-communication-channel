# Secure Inline Communication Channel

**A Linux-based secure inline communication system implemented in C**

## Overview

This project implements a prototype of a secure inline communication channel between two hosts through two intermediate network devices.

The system intercepts selected TCP/IPv4 packets, establishes a shared cryptographic session key between the intermediate devices using Diffie–Hellman key exchange, and protects TCP payloads using AES-256-GCM encryption.

The original IP and TCP headers are preserved during packet processing. The receiving device authenticates and decrypts the protected payload before forwarding the restored packet to its destination.

The project is developed in C using Linux networking capabilities and OpenSSL.

## Network Architecture

The communication follows this topology:

```text
+-------+       +----------+       +----------+       +-------+
|  PC1  | ----> | Device 1 | ----> | Device 2 | ----> |  PC2  |
|Sender |       | Encryptor|       |Decryptor |       |Receiver
+-------+       +----------+       +----------+       +-------+
                     |                   |
                     +--- Secure Session+
```

### Components

- **PC1 (Sender):** Generates and sends TCP traffic.
- **Device1 (Encryptor):** Intercepts selected TCP packets and encrypts their payloads.
- **Device2 (Decryptor):** Verifies authentication tags, decrypts payloads and restores packets.
- **PC2 (Receiver):** Receives the original TCP traffic.

The complete topology is simulated using Linux network namespaces and virtual Ethernet (veth) interfaces.

## Technologies Used

| Technology | Purpose |
|---|---|
| C | Main programming language |
| Linux Network Namespaces | Network isolation |
| Virtual Ethernet (veth) | Virtual network connections |
| TCP/IPv4 | Communication protocol |
| POSIX Sockets | TCP client/server |
| Netfilter / NFQUEUE | Packet interception |
| X25519 | Diffie–Hellman key exchange |
| HKDF-SHA256 | Session key derivation |
| AES-256-GCM | Payload encryption and authentication |
| OpenSSL | Cryptographic operations |
| GCC / Make | Compilation and build automation |

## Security Design

### 1. Key Exchange

Device1 and Device2 establish a shared secret using X25519 key exchange.

The shared secret is processed using HKDF-SHA256 to derive session encryption keys.

### 2. Payload Encryption

Device1 encrypts only the TCP payload using AES-256-GCM.

The authentication tag is appended to the encrypted payload.

The original IP and TCP headers are preserved.

### 3. Payload Decryption

Device2 receives the protected packet, verifies its authentication tag and decrypts the payload.

If authentication fails, the packet is discarded.

### 4. Nonce Management

The implementation must guarantee nonce uniqueness for each independent encryption operation within a session, including correct handling of TCP retransmissions.

## Packet Processing

**Original packet:**

```text
+------------+------------+------------------+
| IP Header  | TCP Header | Original Payload |
+------------+------------+------------------+
```

**Protected packet:**

```text
+------------+------------+-------------+-------------+
| IP Header  | TCP Header | Ciphertext  | GCM Tag     |
+------------+------------+-------------+-------------+
```

The receiving device restores the original payload and recalculates the required IP and TCP checksums.

## Project Structure

```text
secure-inline-communication-channel/
├── network/
│   ├── setup.sh
│   ├── cleanup.sh
│   └── configure_firewall.sh
├── src/
│   ├── common/
│   ├── device1/
│   ├── device2/
│   ├── sender/
│   └── receiver/
├── tests/
├── docs/
├── Makefile
├── README.md
└── .gitignore
```

## Installation

The project targets Linux systems.

Install the required dependencies on Ubuntu/Debian:

```bash
sudo apt update

sudo apt install -y \
    build-essential \
    gcc \
    make \
    libssl-dev \
    libnetfilter-queue-dev \
    libmnl-dev \
    iproute2 \
    iptables \
    tcpdump
```

## Compilation

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/secure-inline-communication-channel.git

cd secure-inline-communication-channel
```

Compile the project:

```bash
make
```

## Running the Project

Create the network topology:

```bash
sudo ./network/setup.sh
```

Start the receiver and sender in their respective network namespaces.

Start Device1 and Device2 to establish the secure session and process protected traffic.

**Note:** Exact execution commands will be added as the implementation is completed.

Clean up the network topology:

```bash
sudo ./network/cleanup.sh
```

## Testing

The following tests are planned:

- Network namespace connectivity.
- TCP file transfer.
- Diffie–Hellman shared secret agreement.
- AES-256-GCM encryption and decryption.
- Authentication tag verification.
- Invalid packet rejection.
- Nonce uniqueness.
- IP and TCP checksum validation.
- File integrity verification using SHA-256.

## Development Status

**Project status: In development**

| Feature | Status |
|---|---|
| Network namespace setup | Planned |
| TCP client/server | Planned |
| X25519 key exchange | Planned |
| HKDF key derivation | Planned |
| AES-256-GCM | Planned |
| Packet interception | Planned |
| Packet restoration | Planned |
| Integration testing | Planned |

Implementation status will be updated as individual components are completed.

## Author

Developed as a university Network Programming project.

**Programming Language:** C  
**Platform:** Linux
