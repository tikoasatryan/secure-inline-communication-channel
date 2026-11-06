/*
 * device - inline security gateway (runs as Device1 = client, Device2 = server)
 *
 * 1. Performs an authenticated X25519 handshake with the peer device over a
 *    separate TCP control connection.
 * 2. Binds two NFQUEUEs:
 *      enc queue : packets coming from the local host side  -> encrypt payload
 *      dec queue : packets coming from the peer device side -> verify + decrypt
 *    Which packets go to which queue is decided by iptables rules (see network/setup.sh).
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <linux/netfilter.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <openssl/crypto.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include "channel.h"

#define MAX_OUT 70000

static channel_t g_ch;
static volatile sig_atomic_t g_stop;

static void on_signal(int s) { (void)s; g_stop = 1; }

/* ---------------------------------------------------------------- handshake */

static int read_full(int fd, void *buf, size_t n)
{
    uint8_t *p = buf;
    while (n) {
        ssize_t r = read(fd, p, n);
        if (r == 0) return -1;
        if (r < 0) { if (errno == EINTR && !g_stop) continue; return -1; }
        p += r; n -= (size_t)r;
    }
    return 0;
}

static int write_full(int fd, const void *buf, size_t n)
{
    const uint8_t *p = buf;
    while (n) {
        ssize_t w = write(fd, p, n);
        if (w < 0) { if (errno == EINTR && !g_stop) continue; return -1; }
        p += w; n -= (size_t)w;
    }
    return 0;
}

static int connect_retry(const char *ip, int port)
{
    for (int i = 0; i < 60 && !g_stop; i++) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in a = {0};
        a.sin_family = AF_INET;
        a.sin_port = htons((uint16_t)port);
        inet_pton(AF_INET, ip, &a.sin_addr);
        if (connect(fd, (struct sockaddr *)&a, sizeof a) == 0) return fd;
        close(fd);
        sleep(1);
    }
    return -1;
}

static int accept_one(const char *ip, int port)
{
    int l = socket(AF_INET, SOCK_STREAM, 0), one = 1;
    setsockopt(l, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, ip, &a.sin_addr) != 1) { close(l); return -1; }
    if (bind(l, (struct sockaddr *)&a, sizeof a) < 0 || listen(l, 1) < 0) {
        perror("bind/listen"); close(l); return -1;
    }
    int fd = accept(l, NULL, NULL);
    close(l);
    return fd;
}

static int handshake(int is_client, const char *ip, int port, const char *psk, session_t *sess)
{
    EVP_PKEY *kp = NULL;
    uint8_t mypub[32], peerpub[32];
    if (dh_generate(&kp, mypub) < 0) { fprintf(stderr, "keygen failed\n"); return -1; }

    int fd = is_client ? connect_retry(ip, port) : accept_one(ip, port);
    if (fd < 0) { fprintf(stderr, "control connection failed\n"); return -1; }

    int rc = -1;
    uint8_t ck[32], mine[32], theirs[32], expect[32];
    const uint8_t *cpub, *spub;

    if (write_full(fd, mypub, 32) < 0 || read_full(fd, peerpub, 32) < 0) goto out;
    cpub = is_client ? mypub : peerpub;
    spub = is_client ? peerpub : mypub;

    if (session_derive(kp, peerpub, cpub, spub, is_client, psk, sess, ck) < 0) goto out;

    /* key confirmation: proves both sides derived the same keys (same PSK, no MITM) */
    if (make_confirm(ck, is_client ? "client" : "server", cpub, spub, mine) < 0) goto out;
    if (write_full(fd, mine, 32) < 0 || read_full(fd, theirs, 32) < 0) goto out;
    if (make_confirm(ck, is_client ? "server" : "client", cpub, spub, expect) < 0) goto out;
    if (CRYPTO_memcmp(theirs, expect, 32) != 0) {
        fprintf(stderr, "key confirmation FAILED (different PSK or active attacker)\n");
        goto out;
    }
    rc = 0;
out:
    OPENSSL_cleanse(ck, sizeof ck);
    EVP_PKEY_free(kp);
    close(fd);
    return rc;
}

/* ------------------------------------------------------------------ NFQUEUE */

struct qctx { int encrypt; };

static int nfq_cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
    (void)nfmsg;
    static uint8_t out[MAX_OUT];
    const struct qctx *q = data;

    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    if (!ph) return 0;
    uint32_t id = ntohl(ph->packet_id);

    unsigned char *pkt = NULL;
    int len = nfq_get_payload(nfa, &pkt);
    if (len < 0) return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);

    int r = q->encrypt ? channel_protect(&g_ch, pkt, len, out, sizeof out)
                       : channel_unprotect(&g_ch, pkt, len, out, sizeof out);

    if (r == PKT_PASS) return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    if (r < 0)         return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    return nfq_set_verdict(qh, id, NF_ACCEPT, (uint32_t)r, out);
}

static void usage(const char *p)
{
    fprintf(stderr,
        "usage: %s --role client|server --ctrl-ip IP [--ctrl-port 9000]\n"
        "          [--psk SECRET | env SC_PSK] [--enc-queue 0] [--dec-queue 1] [-v]\n"
        "  client: --ctrl-ip is the peer device's address\n"
        "  server: --ctrl-ip is the local address to listen on\n", p);
}

int main(int argc, char **argv)
{
    const char *role = NULL, *ip = NULL, *psk = getenv("SC_PSK");
    int port = 9000, qenc = 0, qdec = 1, verbose = 0;

    static const struct option opts[] = {
        {"role", 1, 0, 'r'}, {"ctrl-ip", 1, 0, 'i'}, {"ctrl-port", 1, 0, 'p'},
        {"psk", 1, 0, 'k'}, {"enc-queue", 1, 0, 'e'}, {"dec-queue", 1, 0, 'd'},
        {"verbose", 0, 0, 'v'}, {0, 0, 0, 0}};
    int o;
    while ((o = getopt_long(argc, argv, "r:i:p:k:e:d:v", opts, NULL)) != -1) {
        switch (o) {
        case 'r': role = optarg; break;
        case 'i': ip = optarg; break;
        case 'p': port = atoi(optarg); break;
        case 'k': psk = optarg; break;
        case 'e': qenc = atoi(optarg); break;
        case 'd': qdec = atoi(optarg); break;
        case 'v': verbose = 1; break;
        default: usage(argv[0]); return 2;
        }
    }
    if (!role || !ip || (strcmp(role, "client") && strcmp(role, "server"))) {
        usage(argv[0]); return 2;
    }
    int is_client = !strcmp(role, "client");
    if (!psk || !*psk)
        fprintf(stderr, "WARNING: no PSK set - the handshake is NOT authenticated (MITM possible)\n");

    setvbuf(stdout, NULL, _IOLBF, 0);

    struct sigaction sa = {0};
    sa.sa_handler = on_signal;               /* no SA_RESTART: blocking calls return EINTR */
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    memset(&g_ch, 0, sizeof g_ch);
    g_ch.verbose = verbose;

    printf("[%s] starting handshake...\n", role);
    if (handshake(is_client, ip, port, psk, &g_ch.sess) < 0) return 1;
    printf("[%s] handshake OK: session keys established\n", role);

    struct nfq_handle *h = nfq_open();
    if (!h) { perror("nfq_open (need root / CAP_NET_ADMIN)"); return 1; }

    struct qctx ectx = {1}, dctx = {0};
    struct nfq_q_handle *qe = nfq_create_queue(h, (uint16_t)qenc, nfq_cb, &ectx);
    struct nfq_q_handle *qd = nfq_create_queue(h, (uint16_t)qdec, nfq_cb, &dctx);
    if (!qe || !qd) { fprintf(stderr, "cannot bind queues %d/%d\n", qenc, qdec); return 1; }
    nfq_set_mode(qe, NFQNL_COPY_PACKET, 0xffff);
    nfq_set_mode(qd, NFQNL_COPY_PACKET, 0xffff);
    nfq_set_queue_maxlen(qe, 4096);
    nfq_set_queue_maxlen(qd, 4096);

    printf("[%s] READY (encrypt queue %d, decrypt queue %d)\n", role, qenc, qdec);

    static uint8_t buf[80000];
    int fd = nfq_fd(h);
    while (!g_stop) {
        ssize_t n = recv(fd, buf, sizeof buf, 0);
        if (n >= 0) { nfq_handle_packet(h, (char *)buf, (int)n); continue; }
        if (errno == EINTR || errno == ENOBUFS) continue;
        perror("recv");
        break;
    }

    printf("[%s] stats: encrypted=%llu decrypted=%llu auth_fail=%llu replay=%llu dropped=%llu\n",
           role, (unsigned long long)g_ch.n_enc, (unsigned long long)g_ch.n_dec,
           (unsigned long long)g_ch.n_authfail, (unsigned long long)g_ch.n_replay,
           (unsigned long long)g_ch.n_drop);

    nfq_destroy_queue(qe);
    nfq_destroy_queue(qd);
    nfq_close(h);
    OPENSSL_cleanse(&g_ch.sess, sizeof g_ch.sess);
    return 0;
}
