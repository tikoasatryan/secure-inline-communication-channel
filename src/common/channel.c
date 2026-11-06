#include "channel.h"

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <string.h>
#include "packet.h"

/* Fail closed long before the 64-bit counter space could ever be a concern.
 * (A real product would re-run the DH handshake to rekey here.) */
#define TX_LIMIT (1ULL << 48)

static void put_be64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (56 - 8 * i));
}
static uint64_t get_be64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}

static int replay_ok(const replay_t *r, uint64_t c)
{
    if (!r->init || c > r->max) return 1;
    uint64_t d = r->max - c;
    if (d >= 64) return 0;
    return !((r->bitmap >> d) & 1);
}
static void replay_update(replay_t *r, uint64_t c)
{
    if (!r->init) { r->init = 1; r->max = c; r->bitmap = 1; return; }
    if (c > r->max) {
        uint64_t sh = c - r->max;
        r->bitmap = sh >= 64 ? 0 : r->bitmap << sh;
        r->bitmap |= 1;
        r->max = c;
    } else {
        r->bitmap |= 1ULL << (r->max - c);
    }
}

int channel_protect(channel_t *ch, const uint8_t *in, int in_len, uint8_t *out, int out_cap)
{
    int ihl, hdr, tot;
    if (parse_ipv4_tcp(in, in_len, &ihl, &hdr, &tot) < 0) { ch->n_drop++; return PKT_DROP; }

    int plen = tot - hdr;
    if (plen == 0) return PKT_PASS;                 /* nothing to protect (SYN, ACK, ...) */

    if (tot + OVERHEAD > 65535 || tot + OVERHEAD > out_cap) { ch->n_drop++; return PKT_DROP; }
    if (ch->tx_ctr >= TX_LIMIT)                     { ch->n_drop++; return PKT_DROP; }

    uint64_t ctr = ch->tx_ctr++;                    /* consumed even if encryption fails */
    uint8_t nonce[NONCE_LEN], aad[AAD_LEN], tag[TAG_LEN];
    make_nonce(nonce, ch->sess.tx.salt, ctr);
    build_aad(in, aad);

    memcpy(out, in, hdr);                           /* IP + TCP headers untouched */
    if (gcm_encrypt(ch->sess.tx.key, nonce, aad, AAD_LEN,
                    in + hdr, plen, out + hdr, tag) < 0) { ch->n_drop++; return PKT_DROP; }

    memcpy(out + hdr + plen, tag, TAG_LEN);         /* ciphertext | tag | counter */
    put_be64(out + hdr + plen + TAG_LEN, ctr);

    ((struct iphdr *)out)->tot_len = htons((uint16_t)(tot + OVERHEAD));
    fix_checksums(out);

    ch->n_enc++;
    if (ch->verbose)
        printf("[ENC] ctr=%llu payload=%d -> %d bytes, seq=%u\n",
               (unsigned long long)ctr, plen, plen + OVERHEAD,
               ntohl(((const struct tcphdr *)(in + ihl))->seq));
    return tot + OVERHEAD;
}

int channel_unprotect(channel_t *ch, const uint8_t *in, int in_len, uint8_t *out, int out_cap)
{
    int ihl, hdr, tot;
    if (parse_ipv4_tcp(in, in_len, &ihl, &hdr, &tot) < 0) { ch->n_drop++; return PKT_DROP; }

    int plen = tot - hdr;
    if (plen == 0) return PKT_PASS;
    if (plen <= OVERHEAD || tot > out_cap)          { ch->n_drop++; return PKT_DROP; }

    int cl = plen - OVERHEAD;
    const uint8_t *ct = in + hdr, *tag = ct + cl, *cp = tag + TAG_LEN;
    uint64_t ctr = get_be64(cp);

    if (!replay_ok(&ch->replay, ctr)) {
        ch->n_replay++;
        if (ch->verbose) printf("[REPLAY] ctr=%llu dropped\n", (unsigned long long)ctr);
        return PKT_DROP;
    }

    uint8_t nonce[NONCE_LEN], aad[AAD_LEN];
    make_nonce(nonce, ch->sess.rx.salt, ctr);
    build_aad(in, aad);

    if (gcm_decrypt(ch->sess.rx.key, nonce, aad, AAD_LEN, ct, cl, tag, out + hdr) < 0) {
        ch->n_authfail++;
        if (ch->verbose) printf("[AUTH-FAIL] ctr=%llu dropped\n", (unsigned long long)ctr);
        return PKT_DROP;
    }
    replay_update(&ch->replay, ctr);                /* only after authentication */

    memcpy(out, in, hdr);
    ((struct iphdr *)out)->tot_len = htons((uint16_t)(hdr + cl));
    fix_checksums(out);

    ch->n_dec++;
    if (ch->verbose)
        printf("[DEC] ctr=%llu payload=%d <- %d bytes\n", (unsigned long long)ctr, cl, plen);
    return hdr + cl;
}
