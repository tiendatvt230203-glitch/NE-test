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

/* Encap NE: 14 eth + 4 fid; VLAN+encap: +4 tag → strip 22 */
#define NE_STRIP_ENCAP_PLAIN 18
#define NE_STRIP_ENCAP_VLAN  22

static volatile int           running = 1;
static pthread_mutex_t        wan_log_mx = PTHREAD_MUTEX_INITIALIZER;
static unsigned long long     wan_log_seq;
static unsigned long long     wan_rx_pkts;

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

static void log_wan_frame(unsigned long long seq, const char *tag, const char *wan_if, int rx_q,
                          const uint8_t *pkt, uint32_t len, uint16_t encap_et) {
    if (len < 14u) {
        fprintf(stderr, "[ne-plain] #%llu %s [%s q%d] len=%u (short)\n", seq, tag, wan_if, rx_q,
                len);
        fflush(stderr);
        return;
    }
    char dm[24], sm[24];
    mac_fmt(dm, sizeof dm, pkt);
    mac_fmt(sm, sizeof sm, pkt + 6);
    uint16_t et = ((uint16_t)pkt[12] << 8) | pkt[13];
    fprintf(stderr, "[ne-plain] #%llu %s [%s q%d] len=%u %s>%s et=0x%04x", seq, tag, wan_if, rx_q,
            len, dm, sm, et);

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

/* Chỉ memmove khi outer đúng encap; log của mày đã cho et=0x0800 → trước đó gỡ 18 byte = cắt nát IP
 * (et sau rewrite 0xc0a8 = byte đầu 192.168...). IPv4 thuần: strip=0, chỉ đổi MAC. */
static unsigned strip_wan_outer(const uint8_t *pkt, uint32_t len, uint16_t encap_et) {
    if (encap_et == 0 || len < 14u)
        return 0;
    uint16_t et = ((uint16_t)pkt[12] << 8) | pkt[13];
    if (et == encap_et && len >= NE_STRIP_ENCAP_PLAIN + 14u)
        return NE_STRIP_ENCAP_PLAIN;
    if (et == 0x8100u && len >= NE_STRIP_ENCAP_VLAN + 14u) {
        uint16_t inner = ((uint16_t)pkt[16] << 8) | pkt[17];
        if (inner == encap_et)
            return NE_STRIP_ENCAP_VLAN;
    }
    return 0;
}

/* Sau decap WAN: inner Ethernet DA/SA — trùng quy ước phía gửi WAN (wanX_dst = peer, src = mình):
 * trên inner hướng vào LAN thì DA = local0_src_mac, SA = local0_dst_mac (gói “về” LAN). */
static void wan_strip_mac_print(uint8_t *pkt, uint32_t len, const uint8_t *eth_da,
                                const uint8_t *eth_sa, uint16_t encap_et, const char *wan_if,
                                int rx_q) {
    __atomic_fetch_add(&wan_rx_pkts, 1ULL, __ATOMIC_RELAXED);

    unsigned long long seq;
    pthread_mutex_lock(&wan_log_mx);
    seq = ++wan_log_seq;
    log_wan_frame(seq, "wan_xsk_rx", wan_if, rx_q, pkt, len, encap_et);

    unsigned strip = strip_wan_outer(pkt, len, encap_et);
    if (strip) {
        if (len <= strip) {
            fprintf(stderr, "[ne-plain] #%llu [%s q%d] skip: len=%u strip=%u\n", seq, wan_if, rx_q,
                    len, strip);
            fflush(stderr);
            pthread_mutex_unlock(&wan_log_mx);
            return;
        }
        memmove(pkt, pkt + strip, (size_t)(len - strip));
        len -= strip;
    }

    if (len < 12u) {
        fprintf(stderr, "[ne-plain] #%llu [%s q%d] skip mac rewrite len=%u\n", seq, wan_if, rx_q,
                len);
        fflush(stderr);
        pthread_mutex_unlock(&wan_log_mx);
        return;
    }
    memcpy(pkt, eth_da, 6);
    memcpy(pkt + 6, eth_sa, 6);

    log_wan_frame(seq, "wan_strip_rewrite", wan_if, rx_q, pkt, len, 0);
    pthread_mutex_unlock(&wan_log_mx);
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
    fprintf(stderr, "[ne-plain] wan_worker started wan_idx=%d q=%d (%s)\n", wa->wan_if_idx, q,
            f->cfg && f->cfg->wans[wa->wan_if_idx].ifname[0]
                ? f->cfg->wans[wa->wan_if_idx].ifname
                : "?");
    fflush(stderr);
    int bs = wan->batch_size;
    void    *pkt_ptrs[MAX_BATCH_SIZE];
    uint32_t pkt_lens[MAX_BATCH_SIZE];
    uint64_t addrs[MAX_BATCH_SIZE];
    const uint8_t *eth_da = f->cfg->locals[0].src_mac;
    const uint8_t *eth_sa = f->cfg->locals[0].dst_mac;
    const char    *ifn =
        (f->cfg && f->cfg->wans[wa->wan_if_idx].ifname[0]) ? f->cfg->wans[wa->wan_if_idx].ifname
                                                            : "?";

    while (running) {
        int n = interface_recv_single_queue(wan, q, pkt_ptrs, pkt_lens, addrs, bs);
        if (n <= 0)
            continue;
        for (int i = 0; i < n; i++)
            wan_strip_mac_print((uint8_t *)pkt_ptrs[i], pkt_lens[i], eth_da, eth_sa,
                                f->cfg->encap_ethertype, ifn, q);
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
        fprintf(stderr, "[ne-plain] listen wan[%d] %s RX queues=%d (this iface has AF_XDP workers)\n",
                i, cfg->wans[i].ifname, cfg->wans[i].queue_count);
        fflush(stderr);
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

    fprintf(stderr, "[ne-plain] forwarder_run: wan_count=%d worker_threads=%d\n", fwd->wan_count, nt);
    fflush(stderr);
    if (nt <= 0) {
        fprintf(stderr, "[ne-plain] error: no WAN queues — check config wanN_ifname / queue_count\n");
        fflush(stderr);
        return;
    }

    pthread_t *t = calloc((size_t)nt, sizeof(pthread_t));
    struct wq_arg *wa = calloc((size_t)nt, sizeof(struct wq_arg));
    if (!t || !wa) {
        fprintf(stderr, "[ne-plain] error: alloc threads failed (nt=%d)\n", nt);
        fflush(stderr);
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

    fprintf(stderr,
            "[ne-plain] ok: recv chỉ in khi kernel redirect gói vào XSK — không liên quan app phía gửi "
            "bật/tắt; tắt sender thì không có gói → không có dòng wan_xsk_rx là đúng.\n");
    fflush(stderr);

    int tick = 0;
    unsigned long long last_rx = __atomic_load_n(&wan_rx_pkts, __ATOMIC_RELAXED);
    while (running) {
        sleep(1);
        if (++tick >= 15) {
            tick = 0;
            unsigned long long cur = __atomic_load_n(&wan_rx_pkts, __ATOMIC_RELAXED);
            if (cur == last_rx) {
                fprintf(stderr,
                        "[ne-plain] watchdog: 15s không có gói WAN mới (wan_rx_pkts=%llu) — kiểm tra "
                        "XDP/traffic/sender\n",
                        cur);
                fflush(stderr);
            }
            last_rx = cur;
        }
    }
    for (int i = 0; i < nt; i++)
        pthread_join(t[i], NULL);
    free(t);
    free(wa);
}
