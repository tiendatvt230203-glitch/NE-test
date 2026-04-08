#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} wan_xsks_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u64);
} wan_stats_map SEC(".maps");

/*
 * wan_config_map layout:
 *   [0] = fake_ethertype_ipv4 (u16, network-byte-order) — unused, kept for compat
 *   [1] = fake_ethertype_ipv6 (u16, network-byte-order) — unused, kept for compat
 *   [2] = queue_count (u16, host order)
 *   [3] = encap_ethertype (u16, host order) — e.g. 0x88B5
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u16);
} wan_config_map SEC(".maps");

#define STAT_TOTAL      0
#define STAT_NON_IP     1
#define STAT_REDIRECT   2
#define STAT_NO_SOCK    3
#define STAT_ARP_PASS   4
#define STAT_ICMP_PASS  5
#define IPPROTO_ICMP_VAL 1

static __always_inline void inc_stat(__u32 idx)
{
    __u64 *val = bpf_map_lookup_elem(&wan_stats_map, &idx);
    if (val)
        __sync_fetch_and_add(val, 1);
}

SEC("xdp")
int xdp_wan_redirect_prog(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    inc_stat(STAT_TOTAL);

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 proto = eth->h_proto;
    void *nh    = (void *)(eth + 1);

    /* Strip up to 2 stacked VLAN tags (0x8100 / 0x88a8). */
    for (int tags = 0; tags < 2; tags++) {
        if (proto != __constant_htons(ETH_P_8021Q) &&
            proto != __constant_htons(ETH_P_8021AD))
            break;
        if ((__u8 *)nh + 4 > (__u8 *)data_end)
            return XDP_PASS;
        proto = *(__be16 *)((__u8 *)nh + 2);
        nh    = (__u8 *)nh + 4;
    }

    if (proto == __constant_htons(ETH_P_ARP)) {
        inc_stat(STAT_ARP_PASS);
        return XDP_PASS;
    }

    /* Load encap_ethertype and qcount from config map. */
    __u32 k2 = 2, k3 = 3;
    __u16 *qcountp = bpf_map_lookup_elem(&wan_config_map, &k2);
    __u16 *etp     = bpf_map_lookup_elem(&wan_config_map, &k3);
    __u32 queue_id = ctx->rx_queue_index;

    /* Encapsulated NE frame: EtherType == encap_ethertype (e.g. 0x88B5).
     * First 4 bytes after EtherType are the flow_id — use for queue steering. */
    if (etp && *etp != 0 && proto == bpf_htons(*etp)) {
        if ((__u8 *)nh + 4 <= (__u8 *)data_end) {
            __u32 fid_net;
            __builtin_memcpy(&fid_net, nh, sizeof(fid_net));
            __u32 fid      = bpf_ntohl(fid_net);
            __u16 qcount   = qcountp ? *qcountp : 0;
            if (qcount)
                queue_id = fid % (__u32)qcount;
        }
        goto redirect;
    }

    if (proto == __constant_htons(ETH_P_IP)) {
        struct iphdr *ip = nh;
        if ((void *)(ip + 1) > data_end)
            return XDP_PASS;
        if (ip->protocol == IPPROTO_ICMP_VAL) {
            inc_stat(STAT_ICMP_PASS);
            return XDP_PASS;
        }
        /* For plain IPv4, steer by rx_queue_index (RSS already balanced). */
        goto redirect;
    }

    if (proto == __constant_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = nh;
        if ((void *)(ip6 + 1) > data_end)
            return XDP_PASS;
        if (ip6->nexthdr == IPPROTO_ICMPV6) {
            inc_stat(STAT_ICMP_PASS);
            return XDP_PASS;
        }
        goto redirect;
    }

    inc_stat(STAT_NON_IP);
    return XDP_PASS;

redirect:
    ;
    int ret = bpf_redirect_map(&wan_xsks_map, queue_id, XDP_PASS);
    if (ret == XDP_REDIRECT)
        inc_stat(STAT_REDIRECT);
    else
        inc_stat(STAT_NO_SOCK);
    return ret;
}

char _license[] SEC("license") = "GPL";
