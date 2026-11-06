# Design notes

## Topology

```
PC1 (10.0.1.2) -- Device1 (10.0.1.1 | 10.0.12.1) ==== Device2 (10.0.12.2 | 10.0.2.1) -- PC2 (10.0.2.2)
   plain TCP          encrypt payload      protected      decrypt payload      plain TCP
```

Every node is a Linux network namespace; links are veth pairs. PC1 and PC2 run an
ordinary TCP file transfer and know nothing about the protection. The devices are
IP routers with one extra step in the FORWARD path (Netfilter NFQUEUE).

## Which traffic is protected

TCP packets whose source **or** destination port is 5000 (`network/setup.sh`, variable `PORT`).

* arriving on the host-side interface -> queue 0 -> **encrypt**
* arriving on the peer-side interface -> queue 1 -> **verify + decrypt**

Because the rule is by interface, the same two rules work for both directions of the
connection. TCP packets with an empty payload (SYN, pure ACK, FIN) have nothing to
encrypt and pass unchanged in both directions.

If a device program is not running, nothing is bound to the queues and the kernel
drops the selected packets: no plaintext can leak before a session exists.

## Handshake (control channel)

A separate TCP connection (port 9000) on the device-to-device link. Device1 is the
client, Device2 the server.

```
Device1                                   Device2
  |-- X25519 public key (32 B) ------------>|
  |<-------------- X25519 public key (32 B)-|
  | shared = X25519(priv, peer_pub)         | shared = X25519(priv, peer_pub)
  | okm = HKDF-SHA256(ikm=shared,           | (same)
  |        salt=PSK, info=label|cpub|spub)  |
  |-- HMAC(confirm_key, "client"|cpub|spub)->|
  |<-- HMAC(confirm_key, "server"|cpub|spub)-|
  | both verify the other's HMAC -> READY   |
```

HKDF output (104 bytes): client->server key (32) + salt (4), server->client key (32) +
salt (4), confirmation key (32). The two directions use different keys.

Plain Diffie-Hellman does not authenticate the peers. A pre-shared key (`SC_PSK` or
`--psk`) is mixed into HKDF, and the HMAC key-confirmation step fails if the PSK
differs, which stops an active man-in-the-middle who does not know it.

## Protected packet format

```
 original:   | IP header | TCP header | payload (n bytes)                 |
 protected:  | IP header | TCP header | ciphertext (n) | tag (16) | ctr (8) |
```

* IP and TCP headers are copied unchanged.
* Only the IP total length (+24), the IP checksum and the TCP checksum are recalculated.
* AES-256-GCM, additional authenticated data (AAD, 20 bytes): source IP, destination IP,
  source port, destination port, TCP sequence number, TCP acknowledgment number.
  Changing any of these fields in transit makes the tag check fail.
* No UDP encapsulation and no custom header. The only extra bytes are the tag and
  an 8-byte packet counter placed after it.

## Nonce (unique per packet)

`nonce (12 B) = salt (4 B, from HKDF, per direction) || counter (8 B, big endian)`

* The sender uses a counter that starts at 0 and increases by 1 for every packet
  (also for TCP retransmissions, which arrive as new packets). A counter value is never reused.
* Different directions use different keys, so the same counter value in both directions is safe.
* The counter is sent after the tag, because the receiver cannot guess it
  when packets are lost or reordered.
* The receiver keeps a 64-packet sliding window and rejects replays.
* Hard limit: the sender stops (drops) at 2^48 packets. A product would rekey before.

## Why no TCP sequence-number translation is needed

The encrypted packet exists only on the Device1-Device2 link. No TCP stack terminates a
connection there. Device2 restores the *exact* original packet before PC2 sees it, so
PC1 and PC2 see their own, unmodified sequence/acknowledgment numbers. A retransmission
from PC1 is simply another packet and is encrypted again with a new counter.

## MTU (the one real pitfall)

A protected packet is 24 bytes larger. The kernel checks the forwarding MTU *before* the
FORWARD hook, so Device2 has to forward the still-encrypted packet through its host-side
interface before the program shrinks it. Therefore:

* PCs: MTU 1400 (so TCP MSS = 1360, packets <= 1400)
* devices: MTU 1500 on all interfaces (protected packets <= 1424)

Offloads (GRO/GSO/TSO/checksum) are disabled on all veth interfaces so the kernel does
not deliver oversized or not-yet-checksummed packets to the program.

## Known limitations

* IPv4 + TCP only; IP fragments are dropped.
* One session key per run; no rekeying (restart the devices to rekey).
* TCP headers and packet sizes stay visible (by design of the assignment).
* Educational prototype, not production code.
