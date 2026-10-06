#include "traceroute_cli.h"
#include "dns_resolver.h"

#include <stdio.h>

static int prepare_endpoints(traceroute_config_t *cfg)
{
    if (resolve_target_hostname(cfg->target_name, cfg->target_ip_str,
                               sizeof(cfg->target_ip_str), &cfg->target_addr) < 0) {
        fprintf(stderr, "Error: no se pudo resolver %s.\n", cfg->target_name);
        return -1;
    }
    if (determine_local_ip_for_target(&cfg->target_addr, &cfg->local_addr) < 0) {
        perror("Error: no se pudo determinar la IP local");
        return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    traceroute_config_t cfg;
    int status = traceroute_parse_cli(argc, argv, &cfg);
    if (status != 0) return status > 0 ? 0 : 1;
    if (prepare_endpoints(&cfg) < 0) return 1;
    return traceroute_run(&cfg);
}
