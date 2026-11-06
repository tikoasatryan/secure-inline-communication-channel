# Device1 — Encryptor (planned)

This directory will contain the Device1 NFQUEUE packet handler and the authenticated
Device1–Device2 handshake implementation.

Planned responsibilities:
- Establish/authenticate the session with Device2.
- Select the intended forwarded IPv4/TCP flows.
- Protect packet payloads with AES-256-GCM.
- Manage nonce uniqueness and TCP retransmission behavior.
- Update packet lengths/checksums and reinject the packet.

The transparent TCP sequence-space design must be completed before claiming support.
