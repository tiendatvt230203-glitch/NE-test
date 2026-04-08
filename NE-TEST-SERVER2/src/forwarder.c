#include "../inc/forwarder.h"
#include "../inc/flow_table.h"

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <sched.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <string.h>

static volatile int running            = 1;
static struct flow_table g_flow_table;

static int parse_flow(void *pkt_data, uint32_t pkt_len, uint32_t *src_ip, uint32_t *dst_ip,
                      uint16_t *src_port, uint16_t *dst_port, uint8_t *protocol);

struct queue_thread_args {
    struct forwarder *fwd;
    int               iface_idx;
    int               queue_idx;
    int               tx_queue_base;
    int               wan_worker_index;
    int               cpu_id;
    int               lane_id;
};

static void pin_data_plane_cpu(int cpu_id) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    if (cpu_id < 0)
        cpu_id = NE_PLAIN_CPU;
    CPU_SET(cpu_id, &cpuset);
    (void)pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
}

static int l2_macs_nonzero(const uint8_t *dmac, const uint8_t *smac) {
    int d = dmac[0] | dmac[1] | dmac[2] | dmac[3] | dmac[4] | dmac[5];
    int s = smac[0] | smac[1] | smac[2] | smac[3] | smac[4] | smac[5];
    return d != 0 && s != 0;
}

/* IEEE 802.3: pkt[0..5]=ether_dhost, pkt[6..11]=ether_shost (frame do ta phát ra segment đó). */
static int l2_rewrite_ether(uint8_t *pkt, const uint8_t *dmac, const uint8_t *smac) {
    if (!pkt || !l2_macs_nonzero(dmac, smac))
        return -1;
    memcpy(pkt, dmac, MAC_LEN);
    memcpy(pkt + MAC_LEN, smac, MAC_LEN);
    return 0;
}

static int set_wan_l2_addrs(struct forwarder *fwd, int wan_idx, uint8_t *pkt) {
    if (!fwd || wan_idx < 0 || wan_idx >= fwd->wan_count)
        return -1;
    struct xsk_interface *w = &fwd->wans[wan_idx];
    return l2_rewrite_ether(pkt, w->dst_mac, w->src_mac);
}

#define NE_WAN_ENCAP_FID_LEN 4
#define NE_WAN_ENCAP_LEN (sizeof(struct ether_header) + NE_WAN_ENCAP_FID_LEN)

static uint64_t flow_id_from_5tuple(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port,
                                   uint16_t dst_port, uint8_t protocol) {
    uint64_t x = ((uint64_t)src_ip << 32) ^ (uint64_t)dst_ip;
    x ^= ((uint64_t)src_port << 48) ^ ((uint64_t)dst_port << 32) ^ (uint64_t)protocol;
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdULL;
    x ^= x >> 33;
    x *= 0xc4ceb9fe1a85ec53ULL;
    x ^= x >> 33;
    return x;
}

static int wan_encap_inplace(struct forwarder *fwd, int wan_idx, uint8_t *pkt, uint32_t *pkt_len_io) {
    if (!fwd || !pkt || !pkt_len_io)
        return -1;
    if (wan_idx < 0 || wan_idx >= fwd->wan_count)
        return -1;
    if (!fwd->cfg || fwd->cfg->encap_ethertype == 0)
        return -1;

    struct xsk_interface *wan = &fwd->wans[wan_idx];
    uint32_t pkt_len = *pkt_len_io;
    if (pkt_len + (uint32_t)NE_WAN_ENCAP_LEN > (uint32_t)wan->frame_size)
        return -1;

    uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port;
    uint8_t  proto;
    uint64_t fid = 0;
    if (parse_flow(pkt, pkt_len, &src_ip, &dst_ip, &src_port, &dst_port, &proto) == 0)
        fid = flow_id_from_5tuple(src_ip, dst_ip, src_port, dst_port, proto);
    else
        fid = (uint64_t)pkt_len;

    memmove(pkt + NE_WAN_ENCAP_LEN, pkt, pkt_len);

    struct ether_header *eth = (struct ether_header *)pkt;
    memcpy(eth->ether_dhost, wan->dst_mac, MAC_LEN);
    memcpy(eth->ether_shost, wan->src_mac, MAC_LEN);
    eth->ether_type = htons(fwd->cfg->encap_ethertype);

    uint32_t fid32  = (uint32_t)(fid & 0xffffffffu);
    uint32_t fid_be = htonl(fid32);
    memcpy(pkt + sizeof(*eth), &fid_be, sizeof(fid_be));

    *pkt_len_io = pkt_len + (uint32_t)NE_WAN_ENCAP_LEN;
    return 0;
}

static int wan_decap_inplace(struct forwarder *fwd, uint8_t *pkt, uint32_t *pkt_len_io) {
    if (!fwd || !pkt || !pkt_len_io || !fwd->cfg)
        return -1;
    if (fwd->cfg->encap_ethertype == 0)
        return 1; /* nothing to do */

    uint32_t pkt_len = *pkt_len_io;
    if (pkt_len < (uint32_t)NE_WAN_ENCAP_LEN + (uint32_t)sizeof(struct ether_header))
        return 1;

    struct ether_header *eth = (struct ether_header *)pkt;
    if (ntohs(eth->ether_type) != fwd->cfg->encap_ethertype)
        return 1;

    memmove(pkt, pkt + NE_WAN_ENCAP_LEN, pkt_len - (uint32_t)NE_WAN_ENCAP_LEN);
    *pkt_len_io = pkt_len - (uint32_t)NE_WAN_ENCAP_LEN;
    return 0;
}

static void sigint_handler(int sig) {
    (void)sig;
    running = 0;
}

static int eth_ipv4_offset(const uint8_t *pkt, size_t pkt_len) {
    if (!pkt || pkt_len < 14)
        return -1;
    uint16_t et = ((uint16_t)pkt[12] << 8) | pkt[13];
    if (et == 0x0800)
        return 14;
    if (et == 0x8100) {
        if (pkt_len < 18)
            return -1;
        et = ((uint16_t)pkt[16] << 8) | pkt[17];
        if (et == 0x0800)
            return 18;
        if (et == 0x8100 && pkt_len >= 22) {
            et = ((uint16_t)pkt[20] << 8) | pkt[21];
            if (et == 0x0800)
                return 22;
        }
    }
    return -1;
}

static uint32_t get_dest_ip(void *pkt_data, uint32_t pkt_len) {
    if (pkt_len < sizeof(struct ether_header) + sizeof(struct iphdr))
        return 0;
    struct ether_header *eth = (struct ether_header *)pkt_data;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP)
        return 0;
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    return ip->daddr;
}

static int parse_flow(void *pkt_data, uint32_t pkt_len, uint32_t *src_ip, uint32_t *dst_ip,
                      uint16_t *src_port, uint16_t *dst_port, uint8_t *protocol) {
    uint8_t *pkt = (uint8_t *)pkt_data;
    int l3_off = eth_ipv4_offset(pkt, pkt_len);
    if (l3_off < 0)
        return -1;
    if (pkt_len < (uint32_t)(l3_off + 20))
        return -1;

    struct iphdr *ip = (struct iphdr *)(pkt + l3_off);
    *src_ip      = ip->saddr;
    *dst_ip      = ip->daddr;
    *protocol    = ip->protocol;
    int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < 20)
        return -1;
    uint8_t *transport = pkt + l3_off + ip_hdr_len;

    if (ip->protocol == IPPROTO_TCP) {
        if (pkt_len < (uint32_t)(l3_off + ip_hdr_len + (int)sizeof(struct tcphdr)))
            return -1;
        struct tcphdr *tcp = (struct tcphdr *)transport;
        *src_port = ntohs(tcp->source);
        *dst_port = ntohs(tcp->dest);
    } else if (ip->protocol == IPPROTO_UDP) {
        if (pkt_len < (uint32_t)(l3_off + ip_hdr_len + (int)sizeof(struct udphdr)))
            return -1;
        struct udphdr *udp = (struct udphdr *)transport;
        *src_port = ntohs(udp->source);
        *dst_port = ntohs(udp->dest);
    } else {
        *src_port = *dst_port = 0;
    }
    return 0;
}

#define NE_WAN_LOG_ET 0x88B5u

static void ne_wan_oneframe(char *buf, size_t cap, const uint8_t *p, uint32_t plen) {
    if (!p || plen < 14) {
        snprintf(buf, cap, "short");
        return;
    }
    char dm[24], sm[24];
    snprintf(dm, sizeof dm, "%02x:%02x:%02x:%02x:%02x:%02x", p[0], p[1], p[2], p[3], p[4], p[5]);
    snprintf(sm, sizeof sm, "%02x:%02x:%02x:%02x:%02x:%02x", p[6], p[7], p[8], p[9], p[10], p[11]);
    uint32_t si, di;
    uint16_t sp, dp;
    uint8_t  pr;
    if (parse_flow((void *)p, plen, &si, &di, &sp, &dp, &pr) == 0) {
        char a[INET_ADDRSTRLEN], b[INET_ADDRSTRLEN];
        struct in_addr xa = { .s_addr = si };
        struct in_addr xb = { .s_addr = di };
        inet_ntop(AF_INET, &xa, a, sizeof a);
        inet_ntop(AF_INET, &xb, b, sizeof b);
        if (pr == IPPROTO_TCP)
            snprintf(buf, cap, "%s>%s %s:%u->%s:%u tcp", sm, dm, a, sp, b, dp);
        else if (pr == IPPROTO_UDP)
            snprintf(buf, cap, "%s>%s %s:%u->%s:%u udp", sm, dm, a, sp, b, dp);
        else
            snprintf(buf, cap, "%s>%s %s->%s proto=%u", sm, dm, a, b, pr);
    } else {
        uint16_t et = ((uint16_t)p[12] << 8) | p[13];
        snprintf(buf, cap, "%s>%s et=0x%04x len=%u", sm, dm, et, plen);
    }
}

static int ne_wan_should_log_pkt(const uint8_t *pkt, uint32_t len, uint16_t want_et) {
    if (!pkt)
        return 0;
    if (want_et == 0)
        want_et = NE_WAN_LOG_ET;
    if (len < 14)
        return 0;
    uint16_t et = ((uint16_t)pkt[12] << 8) | pkt[13];
    if (et == want_et)
        return len >= (uint32_t)NE_WAN_ENCAP_LEN + 14u;
    if (et == 0x8100 && len >= 18) {
        et = ((uint16_t)pkt[16] << 8) | pkt[17];
        if (et == want_et)
            return len >= 36u;
    }
    return 0;
}

static void ne_wan_line_xsk_pre(char *buf, size_t cap, const uint8_t *pkt, uint32_t len, uint16_t want_et) {
    if (want_et == 0)
        want_et = NE_WAN_LOG_ET;
    uint32_t fid_off, inner_off;
    uint16_t et = ((uint16_t)pkt[12] << 8) | pkt[13];
    if (et == 0x8100 && len >= 22) {
        fid_off   = 18;
        inner_off = 22;
        et        = ((uint16_t)pkt[16] << 8) | pkt[17];
    } else {
        fid_off   = 14;
        inner_off = (uint32_t)NE_WAN_ENCAP_LEN;
        et        = ((uint16_t)pkt[12] << 8) | pkt[13];
    }
    if (et != want_et || len < inner_off + 14 || len < fid_off + 4) {
        snprintf(buf, cap, "short");
        return;
    }
    uint32_t fid_w;
    memcpy(&fid_w, pkt + fid_off, 4);
    char inner[200];
    ne_wan_oneframe(inner, sizeof inner, pkt + inner_off, len - inner_off);
    snprintf(buf, cap, "len=%u fid=0x%08x %s", len, ntohl(fid_w), inner);
}

static inline uint32_t flow_hash_local_tq(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port,
                                            uint16_t dst_port, uint8_t protocol) {
    uint32_t h = src_ip ^ dst_ip;
    h ^= ((uint32_t)src_port << 16) | dst_port;
    h ^= protocol;
    h ^= (h >> 16);
    h *= 0x85ebca6b;
    h ^= (h >> 13);
    h *= 0xc2b2ae35;
    h ^= (h >> 16);
    return h;
}

static int select_wan_idx_for_packet(struct forwarder *fwd, uint32_t src_ip, uint32_t dst_ip,
                                     uint16_t src_port, uint16_t dst_port, uint8_t protocol,
                                     uint32_t pkt_len) {
    if (!fwd || fwd->wan_count <= 0)
        return 0;
    if (fwd->wan_count == 1)
        return 0;

    int allowed[MAX_INTERFACES];
    int n = fwd->wan_count;
    if (n > MAX_INTERFACES)
        n = MAX_INTERFACES;
    for (int i = 0; i < n; i++)
        allowed[i] = i;

    return flow_table_get_wan_profile(&g_flow_table, src_ip, dst_ip, src_port, dst_port, protocol,
                                      pkt_len, allowed, n, NULL);
}

static void *gc_thread(void *arg) {
    struct forwarder *fwd = (struct forwarder *)arg;
    pin_data_plane_cpu(NE_PLAIN_CPU);
    while (running) {
        sleep(60);
        flow_table_gc(&g_flow_table);
        (void)fwd;
    }
    return NULL;
}

static void *local_queue_thread_no_crypto(void *arg) {
    struct queue_thread_args *args = (struct queue_thread_args *)arg;
    struct forwarder *fwd          = args->fwd;

    pin_data_plane_cpu(args->cpu_id);
    int local_idx = args->iface_idx;
    int queue_idx = args->queue_idx;
    int tx_base   = args->tx_queue_base;

    struct xsk_interface *local    = &fwd->locals[local_idx];
    int                     batch_sz = local->batch_size;

    void    *pkt_ptrs[MAX_BATCH_SIZE];
    uint32_t pkt_lens[MAX_BATCH_SIZE];
    uint64_t addrs[MAX_BATCH_SIZE];

    while (running) {
        int rcvd = interface_recv_single_queue(local, queue_idx, pkt_ptrs, pkt_lens, addrs,
                                               batch_sz);
        if (rcvd <= 0)
            continue;

        int wan_used[MAX_INTERFACES] = {0};
        int wan_tx_q[MAX_INTERFACES];
        for (int w = 0; w < fwd->wan_count; w++)
            wan_tx_q[w] = tx_base % fwd->wans[w].queue_count;

        for (int i = 0; i < rcvd; i++) {
            uint32_t src_ip, dst_ip;
            uint16_t src_port, dst_port;
            uint8_t  protocol;

            int wan_idx;
            if (parse_flow(pkt_ptrs[i], pkt_lens[i], &src_ip, &dst_ip, &src_port, &dst_port,
                           &protocol) == 0) {
                wan_idx = select_wan_idx_for_packet(fwd, src_ip, dst_ip, src_port, dst_port,
                                                    protocol, pkt_lens[i]);
            } else
                wan_idx = 0;

            if (wan_idx < 0 || wan_idx >= fwd->wan_count)
                wan_idx = 0;

            struct xsk_interface *wan = &fwd->wans[wan_idx];
            int                     tq  = wan_tx_q[wan_idx];
            uint8_t                *pkt = (uint8_t *)pkt_ptrs[i];
            uint32_t                out_len = pkt_lens[i];

            if (fwd->cfg && fwd->cfg->encap_ethertype != 0) {
                if (wan_encap_inplace(fwd, wan_idx, pkt, &out_len) != 0) {
                    __sync_fetch_and_add(&fwd->total_dropped, 1);
                    continue;
                }
            } else {
                if (set_wan_l2_addrs(fwd, wan_idx, pkt) != 0) {
                    __sync_fetch_and_add(&fwd->total_dropped, 1);
                    continue;
                }
            }

            if (out_len == 0) {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                continue;
            }

            if (interface_send_batch_queue(wan, tq, pkt, out_len) == 0) {
                __sync_fetch_and_add(&fwd->local_to_wan, 1);
                if (wan_idx >= 0 && wan_idx < MAX_INTERFACES)
                    __sync_fetch_and_add(&fwd->wan_tx_packets[wan_idx], 1);
                wan_used[wan_idx] = 1;
            } else
                __sync_fetch_and_add(&fwd->total_dropped, 1);
        }

        for (int w = 0; w < fwd->wan_count; w++) {
            if (wan_used[w])
                interface_send_flush_queue(&fwd->wans[w], wan_tx_q[w]);
        }

        interface_recv_release_single_queue(local, queue_idx, addrs, rcvd);
    }
    return NULL;
}

static void *wan_queue_thread_no_crypto(void *arg) {
    struct queue_thread_args *args = (struct queue_thread_args *)arg;
    struct forwarder *fwd          = args->fwd;

    pin_data_plane_cpu(args->cpu_id);
    int wan_idx    = args->iface_idx;
    int queue_idx  = args->queue_idx;
    int tx_base    = args->tx_queue_base;

    struct xsk_interface *wan      = &fwd->wans[wan_idx];
    int                   batch_sz = wan->batch_size;

    void    *pkt_ptrs[MAX_BATCH_SIZE];
    uint32_t pkt_lens[MAX_BATCH_SIZE];
    uint64_t addrs[MAX_BATCH_SIZE];

    while (running) {
        int rcvd =
            interface_recv_single_queue(wan, queue_idx, pkt_ptrs, pkt_lens, addrs, batch_sz);
        if (rcvd <= 0)
            continue;

        uint32_t local_used_queues[MAX_INTERFACES] = {0};

        for (int i = 0; i < rcvd; i++) {
            uint8_t *pkt     = (uint8_t *)pkt_ptrs[i];
            uint32_t pkt_len = pkt_lens[i];

            char     wan_pre[384];
            uint16_t want_et =
                (fwd->cfg && fwd->cfg->encap_ethertype != 0) ? fwd->cfg->encap_ethertype : NE_WAN_LOG_ET;
            int wan_log = ne_wan_should_log_pkt(pkt, pkt_len, want_et);
            if (wan_log)
                ne_wan_line_xsk_pre(wan_pre, sizeof wan_pre, pkt, pkt_len, want_et);

            (void)wan_decap_inplace(fwd, pkt, &pkt_len);

            uint32_t dest_ip = get_dest_ip(pkt, pkt_len);
            if (dest_ip == 0) {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                continue;
            }

            int local_idx = config_find_local_for_ip(fwd->cfg, dest_ip);
            if (local_idx < 0) {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                continue;
            }

            struct xsk_interface *local_iface = &fwd->locals[local_idx];
            struct local_config *local_cfg    = &fwd->cfg->locals[local_idx];
            int                  nq           = local_iface->queue_count;
            if (nq <= 0)
                nq = 1;

            int tq;
            {
                uint32_t src_ip, dst_ip;
                uint16_t src_port, dst_port;
                uint8_t  protocol;
                if (parse_flow(pkt, pkt_len, &src_ip, &dst_ip, &src_port, &dst_port, &protocol) ==
                    0)
                    tq = (int)(flow_hash_local_tq(src_ip, dst_ip, src_port, dst_port, protocol) %
                                (uint32_t)nq);
                else
                    tq = args->wan_worker_index >= 0 ? (args->wan_worker_index % nq)
                                                     : (tx_base % nq);
            }

            /* WAN->local TX: dhost=peer LAN, shost=MAC iface local của ne-plain (trùng local_* cfg). */
            if (l2_rewrite_ether(pkt, local_cfg->dst_mac, local_cfg->src_mac) != 0) {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                continue;
            }

            if (wan_log) {
                char post[384];
                ne_wan_oneframe(post, sizeof post, pkt, pkt_len);
                fprintf(stderr, "[ne-plain] xsk: %s | to_local: %s\n", wan_pre, post);
                (void)fflush(stderr);
            }

            if (interface_send_to_local_batch_queue(local_iface, tq, local_cfg, pkt, pkt_len) == 0) {
                __sync_fetch_and_add(&fwd->wan_to_local, 1);
                local_used_queues[local_idx] |= (1u << tq);
            } else
                __sync_fetch_and_add(&fwd->total_dropped, 1);
        }

        for (int l = 0; l < fwd->local_count; l++) {
            if (local_used_queues[l]) {
                for (int q = 0; q < fwd->locals[l].queue_count && q < 32; q++) {
                    if (local_used_queues[l] & (1u << q))
                        interface_send_flush_queue(&fwd->locals[l], q);
                }
            }
        }

        interface_recv_release_single_queue(wan, queue_idx, addrs, rcvd);
    }
    return NULL;
}

static void forwarder_run_no_crypto(struct forwarder *fwd) {
    int local_lane_base[MAX_INTERFACES] = {0};
    int wan_lane_base[MAX_INTERFACES]   = {0};
    {
        int acc = 0;
        for (int i = 0; i < fwd->local_count; i++) {
            local_lane_base[i] = acc;
            acc += fwd->locals[i].queue_count;
        }
    }
    {
        int acc = 0;
        for (int i = 0; i < fwd->wan_count; i++) {
            wan_lane_base[i] = acc;
            acc += fwd->wans[i].queue_count;
        }
    }
    int total_lq = 0;
    for (int i = 0; i < fwd->local_count; i++)
        total_lq += fwd->locals[i].queue_count;
    int total_wq = 0;
    for (int i = 0; i < fwd->wan_count; i++)
        total_wq += fwd->wans[i].queue_count;

    int            total_threads = total_lq + total_wq;
    pthread_t     *threads       = calloc((size_t)total_threads, sizeof(pthread_t));
    struct queue_thread_args *args =
        calloc((size_t)total_threads, sizeof(struct queue_thread_args));
    if (!threads || !args) {
        free(threads);
        free(args);
        fprintf(stderr, "[ne-plain] alloc threads failed\n");
        return;
    }

    pthread_t gc_tid;
    pthread_create(&gc_tid, NULL, gc_thread, fwd);

    int thread_idx = 0;
    for (int i = 0; i < fwd->local_count; i++) {
        struct xsk_interface *loc = &fwd->locals[i];
        for (int q = 0; q < loc->queue_count; q++) {
            int lane = local_lane_base[i] + q;
            args[thread_idx].fwd              = fwd;
            args[thread_idx].iface_idx        = i;
            args[thread_idx].queue_idx        = q;
            args[thread_idx].lane_id          = lane;
            args[thread_idx].tx_queue_base    = lane;
            args[thread_idx].wan_worker_index = -1;
            if (fwd->cfg && fwd->cfg->cpu_lane_base >= 0)
                args[thread_idx].cpu_id = fwd->cfg->cpu_lane_base + lane;
            else
                args[thread_idx].cpu_id = (fwd->cfg ? (fwd->cfg->cpu_local_base + q) : NE_PLAIN_CPU);
            pthread_create(&threads[thread_idx], NULL, local_queue_thread_no_crypto,
                           &args[thread_idx]);
            thread_idx++;
        }
    }

    int wan_worker_idx = 0;
    for (int i = 0; i < fwd->wan_count; i++) {
        struct xsk_interface *w = &fwd->wans[i];
        for (int q = 0; q < w->queue_count; q++) {
            int lane = wan_lane_base[i] + q;
            args[thread_idx].fwd              = fwd;
            args[thread_idx].iface_idx        = i;
            args[thread_idx].queue_idx        = q;
            args[thread_idx].lane_id          = lane;
            args[thread_idx].tx_queue_base    = lane;
            args[thread_idx].wan_worker_index = wan_worker_idx++;
            if (fwd->cfg && fwd->cfg->cpu_lane_base >= 0)
                args[thread_idx].cpu_id = fwd->cfg->cpu_lane_base + lane;
            else
                args[thread_idx].cpu_id = (fwd->cfg ? (fwd->cfg->cpu_wan_base + q) : NE_PLAIN_CPU);
            pthread_create(&threads[thread_idx], NULL, wan_queue_thread_no_crypto,
                           &args[thread_idx]);
            thread_idx++;
        }
    }

    while (running)
        sleep(1);

    for (int i = 0; i < total_threads; i++)
        pthread_join(threads[i], NULL);
    pthread_join(gc_tid, NULL);
    free(threads);
    free(args);
}

int forwarder_init(struct forwarder *fwd, struct app_config *cfg) {
    memset(fwd, 0, sizeof(*fwd));
    fwd->cfg = cfg;
    interface_reset_redirect_maps();

    /* queue_count is configured in config_file.c (or defaults) */

    uint32_t wan_window_sizes[MAX_INTERFACES] = {0};
    for (int i = 0; i < cfg->wan_count && i < MAX_INTERFACES; i++)
        wan_window_sizes[i] = cfg->wans[i].window_size;
    flow_table_init(&g_flow_table, wan_window_sizes, cfg->wan_count);

    for (int i = 0; i < cfg->local_count; i++)
        interface_set_queue_count(cfg->locals[i].ifname, cfg->locals[i].queue_count);
    for (int i = 0; i < cfg->wan_count; i++)
        interface_set_queue_count(cfg->wans[i].ifname, cfg->wans[i].queue_count);

    for (int i = 0; i < cfg->local_count; i++) {
        if (interface_init_local(&fwd->locals[i], &cfg->locals[i], cfg->bpf_local_o) != 0) {
            fprintf(stderr, "init LOCAL %s failed\n", cfg->locals[i].ifname);
            goto err;
        }
        fwd->local_count++;
    }

    if (cfg->redirect.src_count || cfg->redirect.dst_count) {
        if (interface_push_redirect_cfg(&cfg->redirect) != 0)
            fprintf(stderr, "[XDP] redirect map update failed (optional)\n");
    }

    for (int i = 0; i < cfg->wan_count; i++) {
        if (interface_init_wan_rx(&fwd->wans[i], &cfg->wans[i], cfg->bpf_wan_o, 0, 0) != 0) {
            fprintf(stderr, "init WAN %s failed\n", cfg->wans[i].ifname);
            goto err;
        }
        fwd->wan_count++;
    }

    return 0;

err:
    for (int j = 0; j < fwd->wan_count; j++)
        interface_cleanup(&fwd->wans[j]);
    for (int j = 0; j < fwd->local_count; j++)
        interface_cleanup(&fwd->locals[j]);
    flow_table_cleanup(&g_flow_table);
    return -1;
}

void forwarder_cleanup(struct forwarder *fwd) {
    flow_table_cleanup(&g_flow_table);
    for (int i = 0; i < fwd->local_count; i++)
        interface_cleanup(&fwd->locals[i]);
    for (int i = 0; i < fwd->wan_count; i++)
        interface_cleanup(&fwd->wans[i]);
}

void forwarder_run(struct forwarder *fwd) {
    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);
    forwarder_run_no_crypto(fwd);
}
