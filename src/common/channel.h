#ifndef CHANNEL_H
#define CHANNEL_H

#include <stdint.h>
#include "crypto.h"

#define PKT_PASS   0     /* forward unchanged (e.g. TCP packet without payload) */
#define PKT_DROP  (-1)   /* discard                                             */
/* any value > 0 = length of the rewritten packet placed in 'out'                */

typedef struct {
    uint64_t max, bitmap;   /* sliding window of 64 counters */
    int init;
} replay_t;

typedef struct {
    session_t sess;
    uint64_t tx_ctr;        /* next nonce counter; strictly increasing, never reused */
    replay_t replay;
    uint64_t n_enc, n_dec, n_authfail, n_replay, n_drop;
    int verbose;
} channel_t;

/* PC-side packet  ->  protected packet for the peer device */
int channel_protect(channel_t *ch, const uint8_t *in, int in_len, uint8_t *out, int out_cap);
/* protected packet from peer device -> original packet for the host */
int channel_unprotect(channel_t *ch, const uint8_t *in, int in_len, uint8_t *out, int out_cap);

#endif
