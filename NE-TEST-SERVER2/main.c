#include "forwarder.h"
#include "config.h"
#include "cpu_policy.h"
#include <bpf/libbpf.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sched.h>

static int ne_plain_libbpf_print(enum libbpf_print_level level, const char *fmt, va_list ap) {
    if (level == LIBBPF_DEBUG)
        return 0;
    va_list aq;
    va_copy(aq, ap);
    char buf[768];
    vsnprintf(buf, sizeof buf, fmt, aq);
    va_end(aq);
    if (strstr(buf, "Retrying without BTF") != NULL)
        return 0;
    return vfprintf(stderr, fmt, ap);
}

int main(int argc, char **argv) {
    libbpf_set_print(ne_plain_libbpf_print);

    if (argc != 2) {
        fprintf(stderr, "usage: %s <config.cfg>\n", argv[0] ? argv[0] : "ne-plain");
        return EXIT_FAILURE;
    }

    {
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(NE_PLAIN_CPU, &cpuset);
        (void)pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
    }

    struct app_config cfg;
    if (config_load_file(argv[1], &cfg) != 0)
        return EXIT_FAILURE;
    if (config_validate(&cfg) != 0)
        return EXIT_FAILURE;

    struct cpu_policy_state cpu_st;
    if (cpu_policy_apply(&cfg, &cpu_st) != 0) {
        fprintf(stderr, "[cpu-policy] apply failed\n");
        return EXIT_FAILURE;
    }

    struct forwarder fwd;
    if (forwarder_init(&fwd, &cfg) != 0)
    {
        (void)cpu_policy_restore(&cpu_st);
        return EXIT_FAILURE;
    }

    forwarder_run(&fwd);
    forwarder_cleanup(&fwd);
    (void)cpu_policy_restore(&cpu_st);
    return EXIT_SUCCESS;
}
