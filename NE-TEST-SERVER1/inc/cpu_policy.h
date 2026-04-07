#ifndef CPU_POLICY_H
#define CPU_POLICY_H

#include "config.h"

struct cpu_policy_state {
    int enabled;
    char backup_file[512];
};

int cpu_policy_apply(const struct app_config *cfg, struct cpu_policy_state *st);
int cpu_policy_restore(const struct cpu_policy_state *st);

#endif

