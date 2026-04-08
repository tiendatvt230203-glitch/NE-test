#include "../inc/forwarder.h"

#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../inc/config.h"

/* 14 byte eth (encap type + fid) + 4 byte fid = 18 byte gỡ khỏi đầu buffer sau khi nhận từ wan xdp */
#define NE_STRIP_HEAD 18

static volatile int running = 1;

static void sigint_handler(int sig) {
    (void)sig;
    running = 0;
}

/* (1) Nhận batch từ WAN — gọi qua interface_recv_single_queue ở thread. */
/* (2) Gỡ NE_STRIP_HEAD byte + ghi MAC local0 (dst_mac src_mac) + in terminal. */
static void wan_strip_mac_print(uint8_t *pkt, uint32_t len, const uint8_t *dst_mac,
                                const uint8_t *src_mac) {
    memmove(pkt, pkt + NE_STRIP_HEAD, (size_t)(len - NE_STRIP_HEAD));
    len -= NE_STRIP_HEAD;
    memcpy(pkt, dst_mac, 6);
    memcpy(pkt + 6, src_mac, 6);
    fprintf(stderr, "[ne-plain] len=%u\n", len);
    fflush(stderr);
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
            wan_strip_mac_print((uint8_t *)pkt_ptrs[i], pkt_lens[i], dm, sm);
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
