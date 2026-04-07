#include "forwarder.h"
#include "config.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <config.cfg>\n", argv[0] ? argv[0] : "ne-plain");
        return EXIT_FAILURE;
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
