#ifndef CONFIG_PLAIN_H
#define CONFIG_PLAIN_H

#include <stdint.h>
#include <net/if.h>

#define MAX_INTERFACES 16
#define MAC_LEN        6
#define MAX_BATCH_SIZE 1024

#define DEFAULT_FRAME_SIZE    4096
#define DEFAULT_BATCH_SIZE   64
#define DEFAULT_UMEM_MB_LOCAL 256
#define DEFAULT_UMEM_MB_WAN   256
#define DEFAULT_RING_SIZE     4096
#define DEFAULT_QUEUE_COUNT   1

#define MAX_SRC_NETS 32
#define MAX_DST_NETS 32

struct redirect_cfg {
    uint32_t src_net[MAX_SRC_NETS];
    uint32_t src_mask[MAX_SRC_NETS];
    uint32_t src_count;
    uint32_t dst_net[MAX_DST_NETS];
    uint32_t dst_mask[MAX_DST_NETS];
    uint32_t dst_count;
};

struct local_config {
    char     ifname[IF_NAMESIZE];
    uint32_t ip;
    uint32_t netmask;
    uint32_t network;
    uint8_t  src_mac[MAC_LEN];
    uint8_t  dst_mac[MAC_LEN];
    uint32_t umem_mb;
    uint32_t ring_size;
    uint32_t batch_size;
    uint32_t frame_size;
    int      queue_count;
};

struct wan_config {
    char     ifname[IF_NAMESIZE];
    uint32_t dst_ip;
    uint8_t  src_mac[MAC_LEN];
    uint8_t  dst_mac[MAC_LEN];
    uint32_t window_size;
    uint32_t umem_mb;
    uint32_t ring_size;
    uint32_t batch_size;
    uint32_t frame_size;
    int      queue_count;
};

struct app_config {
    uint32_t global_frame_size;
    uint32_t global_batch_size;

    struct local_config locals[MAX_INTERFACES];
    int                 local_count;

    struct wan_config wans[MAX_INTERFACES];
    int                wan_count;

    char bpf_local_o[512];
    char bpf_wan_o[512];

    struct redirect_cfg redirect;
};

int  parse_mac(const char *str, uint8_t *mac);
int  config_load_file(const char *path, struct app_config *cfg);
int  config_validate(struct app_config *cfg);
int  config_find_local_for_ip(struct app_config *cfg, uint32_t dest_ip);

#endif
