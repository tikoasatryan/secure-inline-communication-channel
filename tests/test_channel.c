/* Self-test of crypto + packet processing. Needs no root and no network. */
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>

#include "channel.h"
#include "packet.h"

static int g_fail;
#define CHECK(c, msg) do { if (c) printf("  [ok]   %s\n", msg); \
                           else { printf("  [FAIL] %s\n", msg); g_fail++; } } while (0)

static int build_pkt(uint8_t *p, const char *pl, int plen, uint32_t seq)
{
    memset(p, 0, 40);
    struct iphdr *ip = (struct iphdr *)p;
    ip->version = 4; ip->ihl = 5;
    ip->tot_len = htons((uint16_t)(40 + plen));
    ip->id = htons(1); ip->frag_off = htons(IP_DF);
    ip->ttl = 64; ip->protocol = IPPROTO_TCP;
    ip->saddr = inet_addr("10.0.1.2"); ip->daddr = inet_addr("10.0.2.2");
    struct tcphdr *t = (struct tcphdr *)(p + 20);
    t->source = htons(40000); t->dest = htons(5000);
    t->seq = htonl(seq); t->ack_seq = htonl(1);
    t->doff = 5; t->ack = 1; t->psh = 1; t->window = htons(65535);
    memcpy(p + 40, pl, (size_t)plen);
    fix_checksums(p);
    return 40 + plen;
}

static uint64_t ctr_of(const uint8_t *pkt, int len)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | pkt[len - 8 + i];
    return v;
}

int main(void)
{
    puts("== 1. X25519 + HKDF handshake math ==");
    {
        EVP_PKEY *ka, *kb;
        uint8_t pa[32], pb[32], cka[32], ckb[32], ckc[32];
        session_t sa, sb, sc;
        CHECK(dh_generate(&ka, pa) == 0 && dh_generate(&kb, pb) == 0, "key generation");
        CHECK(session_derive(ka, pb, pa, pb, 1, "psk", &sa, cka) == 0, "client derives session");
        CHECK(session_derive(kb, pa, pa, pb, 0, "psk", &sb, ckb) == 0, "server derives session");
        CHECK(!memcmp(sa.tx.key, sb.rx.key, 32) && !memcmp(sa.tx.salt, sb.rx.salt, 4),
              "client->server keys match");
        CHECK(!memcmp(sa.rx.key, sb.tx.key, 32) && !memcmp(sa.rx.salt, sb.tx.salt, 4),
              "server->client keys match");
        CHECK(memcmp(sa.tx.key, sa.rx.key, 32) != 0, "the two directions use different keys");
        CHECK(!memcmp(cka, ckb, 32), "confirmation keys match");
        session_derive(kb, pa, pa, pb, 0, "other-psk", &sc, ckc);
        CHECK(memcmp(cka, ckc, 32) != 0, "different PSK gives a different confirmation key");
        EVP_PKEY_free(ka); EVP_PKEY_free(kb);
    }

    channel_t A, B;                         /* A = Device1, B = Device2 */
    memset(&A, 0, sizeof A); memset(&B, 0, sizeof B);
    RAND_bytes((uint8_t *)&A.sess, sizeof A.sess);
    B.sess.rx = A.sess.tx;
    B.sess.tx = A.sess.rx;

    static uint8_t orig[2000], enc[2000], dec[2000];
    const char *msg = "SECRET-LINE hello from PC1, this is the TCP payload";
    int plen = (int)strlen(msg);
    int olen = build_pkt(orig, msg, plen, 1000);

    puts("== 2. encrypt / decrypt one packet ==");
    int elen = channel_protect(&A, orig, olen, enc, sizeof enc);
    CHECK(elen == olen + OVERHEAD, "packet grows by exactly tag(16)+counter(8) bytes");
    CHECK(!memcmp(orig + 12, enc + 12, 8) && !memcmp(orig + 20, enc + 20, 16)
          && !memcmp(orig + 38, enc + 38, 2),
          "IP addresses and TCP ports/seq/ack/flags/window are preserved (only checksum recalculated)");
    CHECK(memcmp(enc + 40, msg, (size_t)plen) != 0, "payload is encrypted");
    CHECK(!memmem(enc, (size_t)elen, "SECRET-LINE", 11), "plaintext does not appear in the packet");
    CHECK(verify_checksums(enc), "IP + TCP checksums valid on the encrypted packet");
    int dlen = channel_unprotect(&B, enc, elen, dec, sizeof dec);
    CHECK(dlen == olen && !memcmp(dec, orig, (size_t)olen), "original packet restored byte-for-byte");
    CHECK(verify_checksums(dec), "IP + TCP checksums valid on the restored packet");

    puts("== 3. integrity: modified packets are rejected ==");
    uint8_t bad[2000];
    memcpy(bad, enc, (size_t)elen); bad[45] ^= 1;
    CHECK(channel_unprotect(&B, bad, elen, dec, sizeof dec) == PKT_DROP, "flipped ciphertext bit");
    memcpy(bad, enc, (size_t)elen); bad[40 + plen + 3] ^= 1;
    CHECK(channel_unprotect(&B, bad, elen, dec, sizeof dec) == PKT_DROP, "flipped tag bit");
    memcpy(bad, enc, (size_t)elen); bad[elen - 1] ^= 1;
    CHECK(channel_unprotect(&B, bad, elen, dec, sizeof dec) == PKT_DROP, "changed counter (wrong nonce)");
    memcpy(bad, enc, (size_t)elen); bad[24] ^= 1;
    fix_checksums(bad);
    CHECK(channel_unprotect(&B, bad, elen, dec, sizeof dec) == PKT_DROP, "changed TCP seq (authenticated header field)");
    memcpy(bad, enc, (size_t)elen); bad[12] ^= 1;
    fix_checksums(bad);
    CHECK(channel_unprotect(&B, bad, elen, dec, sizeof dec) == PKT_DROP, "changed source IP (authenticated header field)");

    puts("== 4. replay protection ==");
    CHECK(channel_unprotect(&B, enc, elen, dec, sizeof dec) == PKT_DROP, "same packet delivered a second time");

    puts("== 5. nonce uniqueness ==");
    {
        enum { N = 5000 };
        uint64_t prev = ctr_of(enc, elen);
        int unique = 1;
        for (int i = 0; i < N; i++) {
            int l = build_pkt(orig, msg, plen, 2000u + (uint32_t)i);   /* even identical payloads */
            int e = channel_protect(&A, orig, l, enc, sizeof enc);
            uint64_t c = ctr_of(enc, e);
            if (c != prev + 1) unique = 0;
            prev = c;
        }
        CHECK(unique, "5000 packets -> 5000 distinct, strictly increasing counters");
    }

    puts("== 6. reordering inside the replay window ==");
    {
        channel_t C, D;
        memset(&C, 0, sizeof C); memset(&D, 0, sizeof D);
        RAND_bytes((uint8_t *)&C.sess, sizeof C.sess);
        D.sess.rx = C.sess.tx; D.sess.tx = C.sess.rx;
        uint8_t e[3][2000], o[2000], d[2000];
        int el[3];
        for (int i = 0; i < 3; i++) {
            int l = build_pkt(o, msg, plen, 10u + (uint32_t)i);
            el[i] = channel_protect(&C, o, l, e[i], 2000);
        }
        int ok = channel_unprotect(&D, e[2], el[2], d, sizeof d) > 0
              && channel_unprotect(&D, e[0], el[0], d, sizeof d) > 0
              && channel_unprotect(&D, e[1], el[1], d, sizeof d) > 0;
        CHECK(ok, "packets 3,1,2 all accepted");
    }

    puts("== 7. packets without payload ==");
    {
        uint8_t o[2000], x[2000];
        int l = build_pkt(o, "", 0, 5);
        CHECK(channel_protect(&A, o, l, x, sizeof x) == PKT_PASS, "pure ACK passes unchanged (encrypt side)");
        CHECK(channel_unprotect(&B, o, l, x, sizeof x) == PKT_PASS, "pure ACK passes unchanged (decrypt side)");
    }

    printf("\n%s (%d failure%s)\n", g_fail ? "TESTS FAILED" : "ALL TESTS PASSED", g_fail, g_fail == 1 ? "" : "s");
    return g_fail ? 1 : 0;
}
