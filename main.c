#include "forwarder.h"
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <sched.h>

int main(int argc, char **argv) {
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

    struct forwarder fwd;
    if (forwarder_init(&fwd, &cfg) != 0)
        return EXIT_FAILURE;

    forwarder_run(&fwd);
    forwarder_cleanup(&fwd);
    return EXIT_SUCCESS;
}
