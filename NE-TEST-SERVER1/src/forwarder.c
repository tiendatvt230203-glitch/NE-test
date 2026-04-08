#include "../inc/forwarder.h"

#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "../inc/config.h"

/* 14 byte eth + 4 byte fid (header NE trên WAN trước khi gỡ) */
#define NE_STRIP_HEAD 18

static volatile int running = 1;

static void sigint_handler(int sig) {
    (void)sig;
    running = 0;
}

static void mac_fmt(char *buf, size_t cap, const uint8_t *m) {
    snprintf(buf, cap, "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
}

/* In IPv4 từ saddr/daddr (network endian), không dùng inet_ntop / arpa — không liên quan ARP L2. */
static void ipv4_be_fmt(char *buf, size_t cap, uint32_t addr_be32) {
    const uint8_t *b = (const uint8_t *)&addr_be32;
    snprintf(buf, cap, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
}

static void ip_l4_print(FILE *o, const uint8_t *p, uint32_t len, int ip_off) {
    if (len < (uint32_t)ip_off + 20u)
        return;
    const struct iphdr *ip = (const struct iphdr *)(p + ip_off);
    int ihl = ip->ihl * 4;
    if (ihl < 20 || len < (uint32_t)ip_off + (uint32_t)ihl)
        return;
    char sa[24], da[24];
    ipv4_be_fmt(sa, sizeof sa, ip->saddr);
    ipv4_be_fmt(da, sizeof da, ip->daddr);
    fprintf(o, " | %s->%s proto=%u", sa, da, ip->protocol);
    if (ip->protocol == IPPROTO_TCP && len >= (uint32_t)ip_off + (uint32_t)ihl + 20u) {
        const struct tcphdr *tcp =
            (const struct tcphdr *)((const uint8_t *)ip + (unsigned)ihl);
        fprintf(o, " tcp %u->%u", ntohs(tcp->source), ntohs(tcp->dest));
    } else if (ip->protocol == IPPROTO_UDP && len >= (uint32_t)ip_off + (uint32_t)ihl + 8u) {
        const struct udphdr *udp =
            (const struct udphdr *)((const uint8_t *)ip + (unsigned)ihl);
        fprintf(o, " udp %u->%u", ntohs(udp->source), ntohs(udp->dest));
    }
}

/* In 1 dòng: MAC, ethertype, IPv4+L4 nếu đoán được offset (xsk wan vừa đẩy lên). */
static void log_wan_frame(const char *tag, const uint8_t *pkt, uint32_t len, uint16_t encap_et) {
    if (len < 14u) {
        fprintf(stderr, "[ne-plain] %s len=%u (short)\n", tag, len);
        fflush(stderr);
        return;
    }
    char dm[24], sm[24];
    mac_fmt(dm, sizeof dm, pkt);
    mac_fmt(sm, sizeof sm, pkt + 6);
    uint16_t et = ((uint16_t)pkt[12] << 8) | pkt[13];
    fprintf(stderr, "[ne-plain] %s len=%u %s>%s et=0x%04x", tag, len, dm, sm, et);

    if (et == 0x0800u)
        ip_l4_print(stderr, pkt, len, 14);
    else if (encap_et != 0u && et == encap_et && len >= 32u + 20u)
        ip_l4_print(stderr, pkt, len, 32); /* inner eth14 + ip @32 */
    else if (et == 0x8100u && len >= 50u && encap_et != 0u &&
             ((((uint16_t)pkt[16] << 8) | pkt[17]) == encap_et) && len >= 36u + 20u)
        ip_l4_print(stderr, pkt, len, 36); /* vlan+encap: IP thường @36 */

    fprintf(stderr, "\n");
    fflush(stderr);
}

/* Sau XSK: gỡ header + gán MAC local0 + in trước/sau. */
static void wan_strip_mac_print(uint8_t *pkt, uint32_t len, const uint8_t *dst_mac,
                                const uint8_t *src_mac, uint16_t encap_et) {
    log_wan_frame("wan_xsk_rx", pkt, len, encap_et);

    memmove(pkt, pkt + NE_STRIP_HEAD, (size_t)(len - NE_STRIP_HEAD));
    len -= NE_STRIP_HEAD;
    memcpy(pkt, dst_mac, 6);
    memcpy(pkt + 6, src_mac, 6);

    log_wan_frame("wan_strip_rewrite", pkt, len, 0);
}

struct wq_arg {
    struct forwarder *fwd;
    int               wan_if_idx;
    int               q;
};

static void *wan_worker(void *a) {
    struct wq_arg *wa   = (struct wq_arg *)a;
    struct forwarder *f = wa->fwd;
    struct xsk_interface *wan = &f->wans[wa->wan_if_idx];
    int q  = wa->q;
    int bs = wan->batch_size;
    void    *pkt_ptrs[MAX_BATCH_SIZE];
    uint32_t pkt_lens[MAX_BATCH_SIZE];
    uint64_t addrs[MAX_BATCH_SIZE];
    const uint8_t *dm = f->cfg->locals[0].dst_mac;
    const uint8_t *sm = f->cfg->locals[0].src_mac;

    while (running) {
        int n = interface_recv_single_queue(wan, q, pkt_ptrs, pkt_lens, addrs, bs);
        if (n <= 0)
            continue;
        for (int i = 0; i < n; i++)
            wan_strip_mac_print((uint8_t *)pkt_ptrs[i], pkt_lens[i], dm, sm,
                                f->cfg->encap_ethertype);
        interface_recv_release_single_queue(wan, q, addrs, n);
    }
    return NULL;
}

int forwarder_init(struct forwarder *fwd, struct app_config *cfg) {
    memset(fwd, 0, sizeof(*fwd));
    fwd->cfg = cfg;
    interface_reset_redirect_maps();

    for (int i = 0; i < cfg->wan_count; i++)
        interface_set_queue_count(cfg->wans[i].ifname, cfg->wans[i].queue_count);

    for (int i = 0; i < cfg->wan_count; i++) {
        if (interface_init_wan_rx(&fwd->wans[i], &cfg->wans[i], cfg->bpf_wan_o, 0, 0) != 0) {
            fprintf(stderr, "init WAN %s failed\n", cfg->wans[i].ifname);
            for (int j = 0; j < fwd->wan_count; j++)
                interface_cleanup(&fwd->wans[j]);
            return -1;
        }
        fwd->wan_count++;
    }
    return 0;
}

void forwarder_cleanup(struct forwarder *fwd) {
    for (int i = 0; i < fwd->wan_count; i++)
        interface_cleanup(&fwd->wans[i]);
}

void forwarder_run(struct forwarder *fwd) {
    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    int nt = 0;
    for (int i = 0; i < fwd->wan_count; i++)
        nt += fwd->wans[i].queue_count;

    pthread_t *t = calloc((size_t)nt, sizeof(pthread_t));
    struct wq_arg *wa = calloc((size_t)nt, sizeof(struct wq_arg));
    if (!t || !wa) {
        free(t);
        free(wa);
        return;
    }

    int k = 0;
    for (int i = 0; i < fwd->wan_count; i++) {
        for (int q = 0; q < fwd->wans[i].queue_count; q++) {
            wa[k].fwd       = fwd;
            wa[k].wan_if_idx = i;
            wa[k].q         = q;
            pthread_create(&t[k], NULL, wan_worker, &wa[k]);
            k++;
        }
    }

    while (running)
        sleep(1);
    for (int i = 0; i < nt; i++)
        pthread_join(t[i], NULL);
    free(t);
    free(wa);
}
