#include "../inc/config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>

int parse_mac(const char *str, uint8_t *mac) {
    int v[6];
    if (sscanf(str, "%x:%x:%x:%x:%x:%x", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) != 6)
        return -1;
    for (int i = 0; i < 6; i++)
        mac[i] = (uint8_t)v[i];
    return 0;
}

static int parse_cidr(const char *str, uint32_t *ip, uint32_t *mask, uint32_t *network) {
    char ipbuf[64];
    int pfx;
    if (sscanf(str, "%63[^/]/%d", ipbuf, &pfx) != 2)
        return -1;
    if (pfx < 0 || pfx > 32)
        return -1;
    struct in_addr a;
    if (inet_pton(AF_INET, ipbuf, &a) != 1)
        return -1;
    *ip = a.s_addr;
    if (pfx == 0)
        *mask = 0;
    else
        *mask = htonl(0xFFFFFFFFu << (32 - pfx));
    *network = *ip & *mask;
    return 0;
}

static void trim_inplace(char *s) {
    char *p = s;
    while (*p && isspace((unsigned char)*p))
        p++;
    if (p != s)
        memmove(s, p, strlen(p) + 1);
    size_t n = strlen(s);
    while (n > 0 && isspace((unsigned char)s[n - 1]))
        s[--n] = '\0';
}

int config_load_file(const char *path, struct app_config *cfg) {
    FILE *f = fopen(path, "r");
    if (!f) {
        perror(path);
        return -1;
    }
    memset(cfg, 0, sizeof(*cfg));
    cfg->global_frame_size = DEFAULT_FRAME_SIZE;
    cfg->global_batch_size = DEFAULT_BATCH_SIZE;
    snprintf(cfg->bpf_local_o, sizeof(cfg->bpf_local_o), "bpf/xdp_redirect.o");
    snprintf(cfg->bpf_wan_o, sizeof(cfg->bpf_wan_o), "bpf/xdp_wan_redirect.o");

    int max_local = -1, max_wan = -1;
    char line[512];

    while (fgets(line, sizeof(line), f)) {
        char *p = strchr(line, '\n');
        if (p) *p = '\0';
        if (line[0] == '#' || line[0] == '\0')
            continue;
        char *eq = strchr(line, '=');
        if (!eq)
            continue;
        *eq = '\0';
        char *key = line;
        char *val = eq + 1;
        trim_inplace(key);
        trim_inplace(val);

        if (strcmp(key, "global_frame_size") == 0)
            cfg->global_frame_size = (uint32_t)strtoul(val, NULL, 10);
        else if (strcmp(key, "global_batch_size") == 0)
            cfg->global_batch_size = (uint32_t)strtoul(val, NULL, 10);
        else if (strcmp(key, "bpf_local") == 0)
            snprintf(cfg->bpf_local_o, sizeof(cfg->bpf_local_o), "%s", val);
        else if (strcmp(key, "bpf_wan") == 0)
            snprintf(cfg->bpf_wan_o, sizeof(cfg->bpf_wan_o), "%s", val);
        else {
            int idx;
            char suffix[64];
            if (sscanf(key, "local%d_%63s", &idx, suffix) == 2) {
                if (idx < 0 || idx >= MAX_INTERFACES)
                    continue;
                if (idx > max_local)
                    max_local = idx;
                struct local_config *L = &cfg->locals[idx];
                if (strcmp(suffix, "ifname") == 0)
                    snprintf(L->ifname, sizeof(L->ifname), "%s", val);
                else if (strcmp(suffix, "cidr") == 0) {
                    if (parse_cidr(val, &L->ip, &L->netmask, &L->network) != 0)
                        fprintf(stderr, "[cfg] bad local%d_cidr %s\n", idx, val);
                } else if (strcmp(suffix, "src_mac") == 0)
                    (void)parse_mac(val, L->src_mac);
                else if (strcmp(suffix, "dst_mac") == 0)
                    (void)parse_mac(val, L->dst_mac);
                else if (strcmp(suffix, "umem_mb") == 0)
                    L->umem_mb = (uint32_t)strtoul(val, NULL, 10);
                else if (strcmp(suffix, "ring_size") == 0)
                    L->ring_size = (uint32_t)strtoul(val, NULL, 10);
                else if (strcmp(suffix, "batch_size") == 0)
                    L->batch_size = (uint32_t)strtoul(val, NULL, 10);
            } else if (sscanf(key, "wan%d_%63s", &idx, suffix) == 2) {
                if (idx < 0 || idx >= MAX_INTERFACES)
                    continue;
                if (idx > max_wan)
                    max_wan = idx;
                struct wan_config *W = &cfg->wans[idx];
                if (strcmp(suffix, "ifname") == 0)
                    snprintf(W->ifname, sizeof(W->ifname), "%s", val);
                else if (strcmp(suffix, "dst_ip") == 0) {
                    if (strcmp(val, "0") == 0 || strcasecmp(val, "none") == 0)
                        W->dst_ip = 0;
                    else {
                        struct in_addr a;
                        if (inet_pton(AF_INET, val, &a) == 1)
                            W->dst_ip = a.s_addr;
                    }
                } else if (strcmp(suffix, "src_mac") == 0)
                    (void)parse_mac(val, W->src_mac);
                else if (strcmp(suffix, "dst_mac") == 0)
                    (void)parse_mac(val, W->dst_mac);
                else if (strcmp(suffix, "window_kb") == 0)
                    W->window_size = (uint32_t)strtoul(val, NULL, 10) * 1024u;
                else if (strcmp(suffix, "umem_mb") == 0)
                    W->umem_mb = (uint32_t)strtoul(val, NULL, 10);
                else if (strcmp(suffix, "ring_size") == 0)
                    W->ring_size = (uint32_t)strtoul(val, NULL, 10);
                else if (strcmp(suffix, "batch_size") == 0)
                    W->batch_size = (uint32_t)strtoul(val, NULL, 10);
            }
        }
    }
    fclose(f);

    cfg->local_count = (max_local >= 0) ? (max_local + 1) : 0;
    cfg->wan_count   = (max_wan >= 0) ? (max_wan + 1) : 0;

    for (int i = 0; i < cfg->local_count; i++) {
        struct local_config *L = &cfg->locals[i];
        if (L->frame_size == 0)
            L->frame_size = cfg->global_frame_size;
        if (L->batch_size == 0)
            L->batch_size = cfg->global_batch_size;
        if (L->umem_mb == 0)
            L->umem_mb = DEFAULT_UMEM_MB_LOCAL;
        if (L->ring_size == 0)
            L->ring_size = DEFAULT_RING_SIZE;
        L->queue_count = DEFAULT_QUEUE_COUNT;
    }
    for (int i = 0; i < cfg->wan_count; i++) {
        struct wan_config *W = &cfg->wans[i];
        if (W->frame_size == 0)
            W->frame_size = cfg->global_frame_size;
        if (W->batch_size == 0)
            W->batch_size = cfg->global_batch_size;
        if (W->umem_mb == 0)
            W->umem_mb = DEFAULT_UMEM_MB_WAN;
        if (W->ring_size == 0)
            W->ring_size = DEFAULT_RING_SIZE;
        if (W->window_size == 0)
            W->window_size = 2048u * 1024u;
        W->queue_count = DEFAULT_QUEUE_COUNT;
    }

    return 0;
}

int config_validate(struct app_config *cfg) {
    if (!cfg)
        return -1;
    if (cfg->global_frame_size == 0 || cfg->global_batch_size == 0) {
        fprintf(stderr, "[cfg] global_frame_size / global_batch_size required\n");
        return -1;
    }
    for (int i = 0; i < cfg->local_count; i++) {
        struct local_config *L = &cfg->locals[i];
        if (L->ifname[0] == '\0') {
            fprintf(stderr, "[cfg] local[%d] ifname missing\n", i);
            return -1;
        }
        if (L->netmask == 0 && L->network == 0 && L->ip == 0) {
            fprintf(stderr, "[cfg] local[%s] cidr missing\n", L->ifname);
            return -1;
        }
    }
    for (int i = 0; i < cfg->wan_count; i++) {
        struct wan_config *W = &cfg->wans[i];
        if (W->ifname[0] == '\0') {
            fprintf(stderr, "[cfg] wan[%d] ifname missing\n", i);
            return -1;
        }
        if (W->window_size == 0) {
            fprintf(stderr, "[cfg] wan[%s] window_kb/window_size missing\n", W->ifname);
            return -1;
        }
    }
    return 0;
}

int config_find_local_for_ip(struct app_config *cfg, uint32_t dest_ip) {
    for (int i = 0; i < cfg->local_count; i++) {
        struct local_config *local = &cfg->locals[i];
        if ((dest_ip & local->netmask) == local->network)
            return i;
    }
    return -1;
}
