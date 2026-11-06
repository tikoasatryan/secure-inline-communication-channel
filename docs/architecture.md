# Architecture and design decisions

## Topology

```text
PC1 (10.0.1.2)
    |
Device1 ingress (10.0.1.1)
Device1 egress  (10.0.12.1)
    |
Device2 ingress (10.0.12.2)
Device2 egress  (10.0.2.1)
    |
PC2 (10.0.2.2)
```

Four Linux network namespaces are connected by three veth pairs. Device1 and
Device2 route IPv4 traffic between their two interfaces.

## Crypto design

- X25519 produces a shared secret.
- HKDF-SHA256 derives a 32-byte AES key.
- AES-256-GCM provides confidentiality and integrity.
- GCM tag length: 16 bytes.
- GCM nonce length: 12 bytes.

The current crypto test is a local self-test, not a network handshake. A production
handshake needs peer authentication, transcript binding, key confirmation, and
separate directional keys.

## TCP transparency challenge

TCP is a byte stream. Adding a 16-byte tag to each intercepted segment changes
the sequence-space seen by the receiver. A transparent middlebox therefore needs
a coherent TCP transformation design, including sequence and acknowledgment
number translation, retransmission caching, segmentation/coalescing, out-of-order
handling, connection teardown, and both directions. Updating only IP/TCP checksums
is insufficient.

## Nonce design

The receiver must know the nonce for each protected packet. Nonces must never
repeat under a key. A deterministic nonce derived from flow identity and sequence
space requires careful uniqueness and retransmission rules. Transmitting the
nonce in-band changes the payload framing. Confirm the acceptable interpretation
of "no custom protocol header" with the instructor before implementation.

## Checksums and MTU

After modifying packet bytes, update IPv4 total length and IPv4 header checksum,
as well as TCP checksum (including the IPv4 pseudo-header). Account for MTU and
fragmentation behavior. Disable or account for segmentation/checksum offloads
during packet-capture tests.
