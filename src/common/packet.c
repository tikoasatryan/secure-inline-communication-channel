#include "packet.h"

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>

static uint32_t csum_add(uint32_t sum, const uint8_t *p, size_t len)
{
    while (len > 1) { sum += (uint32_t)((p[0] << 8) | p[1]); p += 2; len -= 2; }
    if (len) sum += (uint32_t)(p[0] << 8);
    return sum;
}

static uint16_t csum_fold(uint32_t sum)
{
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

static uint16_t tcp_sum(const uint8_t *pkt, int ihl, int tot)
{
    const struct iphdr *ip = (const struct iphdr *)pkt;
    uint32_t s = 0;
    s = csum_add(s, (const uint8_t *)&ip->saddr, 4);   /* pseudo header */
    s = csum_add(s, (const uint8_t *)&ip->daddr, 4);
    s += IPPROTO_TCP;
    s += (uint32_t)(tot - ihl);
    s = csum_add(s, pkt + ihl, (size_t)(tot - ihl));
    return csum_fold(s);
}

int parse_ipv4_tcp(const uint8_t *pkt, int len, int *ihl_o, int *hdr_o, int *tot_o)
{
    if (len < (int)sizeof(struct iphdr)) return -1;
    const struct iphdr *ip = (const struct iphdr *)pkt;
    if (ip->version != 4 || ip->protocol != IPPROTO_TCP) return -1;
    int ihl = ip->ihl * 4;
    int tot = ntohs(ip->tot_len);
    if (ihl < 20 || tot < ihl + 20 || tot > len) return -1;
    if (ntohs(ip->frag_off) & (IP_MF | IP_OFFMASK)) return -1;   /* no fragments */
    const struct tcphdr *tcp = (const struct tcphdr *)(pkt + ihl);
    int thl = tcp->doff * 4;
    if (thl < 20 || ihl + thl > tot) return -1;
    *ihl_o = ihl; *hdr_o = ihl + thl; *tot_o = tot;
    return 0;
}

void fix_checksums(uint8_t *pkt)
{
    struct iphdr *ip = (struct iphdr *)pkt;
    int ihl = ip->ihl * 4, tot = ntohs(ip->tot_len);
    struct tcphdr *tcp = (struct tcphdr *)(pkt + ihl);

    ip->check = 0;
    ip->check = htons(csum_fold(csum_add(0, pkt, (size_t)ihl)));
    tcp->check = 0;
    tcp->check = htons(tcp_sum(pkt, ihl, tot));
}

int verify_checksums(const uint8_t *pkt)
{
    const struct iphdr *ip = (const struct iphdr *)pkt;
    int ihl = ip->ihl * 4, tot = ntohs(ip->tot_len);
    return csum_fold(csum_add(0, pkt, (size_t)ihl)) == 0 && tcp_sum(pkt, ihl, tot) == 0;
}

void build_aad(const uint8_t *pkt, uint8_t aad[AAD_LEN])
{
    const struct iphdr *ip = (const struct iphdr *)pkt;
    const struct tcphdr *tcp = (const struct tcphdr *)(pkt + ip->ihl * 4);
    memcpy(aad,      &ip->saddr,    4);
    memcpy(aad + 4,  &ip->daddr,    4);
    memcpy(aad + 8,  &tcp->source,  2);
    memcpy(aad + 10, &tcp->dest,    2);
    memcpy(aad + 12, &tcp->seq,     4);
    memcpy(aad + 16, &tcp->ack_seq, 4);
}
