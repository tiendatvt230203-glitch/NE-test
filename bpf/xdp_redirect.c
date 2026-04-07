#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/ipv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>


#define MAX_SRC_NETS 32
#define MAX_DST_NETS 32
#define IPPROTO_ICMP_VAL   1
#define ETH_P_ARP_VAL      0x0806

struct redirect_cfg {
    __u32 src_net[MAX_SRC_NETS];
    __u32 src_mask[MAX_SRC_NETS];
    __u32 src_count;

    __u32 dst_net[MAX_DST_NETS];
    __u32 dst_mask[MAX_DST_NETS];
    __u32 dst_count;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u64);
} stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct redirect_cfg);
} config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} xsks_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u32);
} xsk_params_map SEC(".maps");

static __always_inline __u32 bswap32(__u32 x)
{
    return bpf_htonl(x);
}

static __always_inline void inc_stat(__u32 idx)
{
    __u64 *val = bpf_map_lookup_elem(&stats_map, &idx);
    if (val)
        __sync_fetch_and_add(val, 1);
}

static __always_inline int parse_ipv4_at(void *nh, void *data_end, __u32 *src_ip,
                                        __u32 *dst_ip, __u8 *proto)
{
    struct iphdr *ip = nh;
    if ((void *)(ip + 1) > data_end)
        return -1;
    if (ip->ihl < 5)
        return -1;

    *src_ip = ip->saddr;
    *dst_ip = ip->daddr;
    if (proto)
        *proto = ip->protocol;
    return 0;
}

static __always_inline int ip_in_net(__u32 ip, __u32 net, __u32 mask)
{
    return (ip & mask) == (net & mask);
}

SEC("xdp")
int xdp_redirect_prog(struct xdp_md *ctx)
{
    inc_stat(0);

    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end) {
        inc_stat(1);
        return XDP_PASS;
    }

    __u16 proto = eth->h_proto;
    void *nh    = (void *)(eth + 1);

    if (proto == bpf_htons(ETH_P_8021Q)) {
        if ((__u8 *)nh + 4 > (__u8 *)data_end) {
            inc_stat(1);
            return XDP_PASS;
        }
        __be16 *ipe = (__be16 *)((__u8 *)nh + 2);
        proto       = *ipe;
        nh          = (void *)((__u8 *)nh + 4);
    }

    if (proto == bpf_htons(ETH_P_ARP_VAL)) {
        inc_stat(7);
        return XDP_PASS;
    }

    if (proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = nh;
        if ((void *)(ip6 + 1) > data_end) {
            inc_stat(1);
            return XDP_PASS;
        }
        if (ip6->nexthdr == IPPROTO_ICMPV6) {
            inc_stat(4);
            return XDP_PASS;
        }
        inc_stat(1);
        return XDP_PASS;
    }

    /* Optional: steer encrypted frames by flow_id in a custom EtherType.
     * xsk_params_map[0] = qcount
     * xsk_params_map[1] = flow_ethertype (host order)
     */
    __u32 k0 = 0, k1 = 1;
    __u32 *qcountp = bpf_map_lookup_elem(&xsk_params_map, &k0);
    __u32 *etp     = bpf_map_lookup_elem(&xsk_params_map, &k1);
    if (etp && *etp != 0 && proto == bpf_htons((__u16)*etp)) {
        if ((__u8 *)nh + 4 <= (__u8 *)data_end) {
            __u32 fid_net;
            __builtin_memcpy(&fid_net, nh, sizeof(fid_net));
            __u32 fid = bswap32(fid_net);
            __u32 qcount = qcountp ? *qcountp : 0;
            __u32 qid = qcount ? (__u32)(fid % qcount) : ctx->rx_queue_index;
            int *sock = bpf_map_lookup_elem(&xsks_map, &qid);
            if (sock) {
                inc_stat(6);
                return bpf_redirect_map(&xsks_map, qid, 0);
            }
        }
        inc_stat(5);
        return XDP_PASS;
    }

    if (proto != bpf_htons(ETH_P_IP)) {
        inc_stat(1);
        return XDP_PASS;
    }

    __u32 src_ip, dst_ip;
    __u8 l4_proto = 0;
    if (parse_ipv4_at(nh, data_end, &src_ip, &dst_ip, &l4_proto) < 0) {
        inc_stat(1);
        return XDP_PASS;
    }

    if (l4_proto == IPPROTO_ICMP_VAL) {
        inc_stat(4);
        return XDP_PASS;
    }

    __u32 cfg_key = 0;
    struct redirect_cfg *cfg = bpf_map_lookup_elem(&config_map, &cfg_key);
    if (!cfg) {
        inc_stat(2);
        return XDP_PASS;
    }

    int src_ok = (cfg->src_count == 0);
    int dst_ok = (cfg->dst_count == 0);

    for (int i = 0; i < MAX_SRC_NETS; i++) {
        if ((__u32)i < cfg->src_count &&
            ip_in_net(src_ip, cfg->src_net[i], cfg->src_mask[i])) {
            src_ok = 1;
            break;
        }
    }

    for (int i = 0; i < MAX_DST_NETS; i++) {
        if ((__u32)i < cfg->dst_count &&
            ip_in_net(dst_ip, cfg->dst_net[i], cfg->dst_mask[i])) {
            dst_ok = 1;
            break;
        }
    }

    if (!(src_ok && dst_ok)) {
        inc_stat(3);
        return XDP_PASS;
    }

    __u32 qid = ctx->rx_queue_index;
    int *sock = bpf_map_lookup_elem(&xsks_map, &qid);
    if (!sock) {
        inc_stat(5);
        return XDP_PASS;
    }

    inc_stat(6);
    return bpf_redirect_map(&xsks_map, qid, 0);
}

char _license[] SEC("license") = "GPL";
