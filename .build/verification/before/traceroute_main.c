#include "traceroute_engine.h"
#include "dns_resolver.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void print_usage(const char *prog)
{
    printf("\nUso: %s [opciones] <destino>\n\n", prog);
    printf("Opciones:\n");
    printf("  -f, --first-ttl <num>  TTL inicial (Default: %d)\n", DEFAULT_FIRST_TTL);
    printf("  -m, --max-hops <num>   Cantidad maxima de saltos (Default: %d)\n", DEFAULT_MAX_HOPS);
    printf("  -q, --probes <num>     Probes por cada salto (Default: %d)\n", DEFAULT_PROBES);
    printf("  -w, --timeout <seg>    Timeout de espera en segundos (Default: %d)\n", DEFAULT_TIMEOUT_SEC);
    printf("  -z, --pause <ms>       Pausa entre probes en milisegundos (Default: %d)\n", DEFAULT_PAUSE_MS);
    printf("  -h, --help             Muestra esta ayuda\n\n");
}

static void init_default_config(traceroute_config_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->first_ttl       = DEFAULT_FIRST_TTL;
    cfg->max_hops        = DEFAULT_MAX_HOPS;
    cfg->probes_per_hop  = DEFAULT_PROBES;
    cfg->timeout_sec     = DEFAULT_TIMEOUT_SEC;
    cfg->pause_ms        = DEFAULT_PAUSE_MS;
    cfg->base_dst_port   = DEFAULT_BASE_PORT;
    cfg->local_src_port  = (uint16_t)(40000 + (getpid() & 0x3FFF));
}

static int parse_flag_value(const char *flag, const char *val, traceroute_config_t *cfg)
{
    if (!strcmp(flag, "-f") || !strcmp(flag, "--first-ttl")) cfg->first_ttl = (uint8_t)atoi(val);
    else if (!strcmp(flag, "-m") || !strcmp(flag, "--max-hops")) cfg->max_hops = (uint8_t)atoi(val);
    else if (!strcmp(flag, "-q") || !strcmp(flag, "--probes")) cfg->probes_per_hop = (uint8_t)atoi(val);
    else if (!strcmp(flag, "-w") || !strcmp(flag, "--timeout")) cfg->timeout_sec = atoi(val);
    else if (!strcmp(flag, "-z") || !strcmp(flag, "--pause")) cfg->pause_ms = atoi(val);
    else return -1;
    return 0;
}

static int parse_single_cli_argument(int *i, int argc, char **argv,
                                     traceroute_config_t *cfg, const char **target_arg)
{
    const char *arg = argv[*i];
    if (!strcmp(arg, "-h") || !strcmp(arg, "--help")) {
        print_usage(argv[0]);
        return 1;
    }
    if (arg[0] == '-') {
        if (++(*i) >= argc) {
            fprintf(stderr, "Error: Falta valor para %s\n", arg);
            return -1;
        }
        return parse_flag_value(arg, argv[*i], cfg);
    }
    *target_arg = arg;
    return 0;
}

/* Orquestador que cumple con modularCoding (<= 15 lineas) */
static int parse_cli_arguments(int argc, char **argv, traceroute_config_t *cfg,
                               const char **target_arg)
{
    if (argc < 2) {
        print_usage(argv[0]);
        return -1;
    }
    for (int i = 1; i < argc; i++) {
        int rc = parse_single_cli_argument(&i, argc, argv, cfg, target_arg);
        if (rc != 0) return rc;
    }
    if (!*target_arg) {
        fprintf(stderr, "Error: Se debe especificar un destino.\n");
        return -1;
    }
    return 0;
}

/* Orquestador que cumple con modularCoding (<= 15 lineas) */
static int resolve_and_prepare_endpoints(const char *target_arg, traceroute_config_t *cfg)
{
    strncpy(cfg->target_name, target_arg, sizeof(cfg->target_name) - 1);
    if (resolve_target_hostname(target_arg, cfg->target_ip_str,
                                sizeof(cfg->target_ip_str), &cfg->target_addr) < 0) {
        fprintf(stderr, "Error: No se pudo resolver el host: %s\n", target_arg);
        return -1;
    }
    if (determine_local_ip_for_target(&cfg->target_addr, cfg->local_ip_str,
                                      sizeof(cfg->local_ip_str)) < 0) {
        strncpy(cfg->local_ip_str, "0.0.0.0", sizeof(cfg->local_ip_str));
    }
    return 0;
}

/* Orquestador principal de entrada que cumple con modularCoding (<= 15 lineas) */
int main(int argc, char **argv)
{
    traceroute_config_t cfg;
    init_default_config(&cfg);

    const char *target_arg = NULL;
    int rc = parse_cli_arguments(argc, argv, &cfg, &target_arg);
    if (rc != 0) return (rc > 0) ? 0 : 1;

    if (resolve_and_prepare_endpoints(target_arg, &cfg) != 0) return 1;

    return traceroute_run(&cfg);
}
