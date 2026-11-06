#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>
#include "common.h"

/* Validate an IPv4/TCP packet (no fragments). Returns 0 and fills the lengths:
 *   ihl = IP header bytes, hdr = IP+TCP header bytes, tot = IP total length. */
int parse_ipv4_tcp(const uint8_t *pkt, int len, int *ihl, int *hdr, int *tot);

/* Recompute IP header checksum and TCP checksum in place. */
void fix_checksums(uint8_t *pkt);

/* Returns 1 if both checksums are valid. */
int verify_checksums(const uint8_t *pkt);

/* AAD = src ip | dst ip | sport | dport | seq | ack  (fields no middlebox changes) */
void build_aad(const uint8_t *pkt, uint8_t aad[AAD_LEN]);

#endif
