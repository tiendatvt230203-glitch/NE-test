#ifndef FORWARDER_PLAIN_H
#define FORWARDER_PLAIN_H

#include "interface.h"

struct forwarder {
    struct xsk_interface locals[MAX_INTERFACES];
    int                  local_count;

    struct xsk_interface wans[MAX_INTERFACES];
    int                  wan_count;

    struct app_config *cfg;

    uint64_t local_to_wan;
    uint64_t wan_to_local;
    uint64_t total_dropped;
};

int  forwarder_init(struct forwarder *fwd, struct app_config *cfg);
void forwarder_cleanup(struct forwarder *fwd);
void forwarder_run(struct forwarder *fwd);

#endif
