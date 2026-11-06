# Device2 — Decryptor (planned)

This directory will contain the Device2 NFQUEUE packet handler and peer handshake.

Planned responsibilities:
- Authenticate Device1 and establish matching session keys.
- Identify protected packets and recover the nonce/framing.
- Verify the GCM tag before releasing plaintext.
- Restore the original payload and recalculate checksums.
- Forward valid restored packets; drop authentication failures.
