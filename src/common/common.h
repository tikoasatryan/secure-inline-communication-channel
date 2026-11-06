#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>

#define KEY_LEN    32   /* AES-256 */
#define SALT_LEN   4    /* fixed part of the GCM nonce, derived per direction */
#define NONCE_LEN  12   /* salt(4) || counter(8) */
#define TAG_LEN    16   /* GCM authentication tag */
#define CTR_LEN    8    /* explicit packet counter appended after the tag */
#define OVERHEAD   (TAG_LEN + CTR_LEN)
#define AAD_LEN    20   /* src ip, dst ip, sport, dport, seq, ack */

#endif
