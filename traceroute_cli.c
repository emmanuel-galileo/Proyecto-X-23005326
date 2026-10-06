#include "traceroute_cli.h"

#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const struct option long_options[] = {
    {"first-ttl", required_argument, NULL, 'f'},
    {"max-hops", required_argument, NULL, 'm'},
    {"probes", required_argument, NULL, 'q'},
    {"timeout", required_argument, NULL, 'w'},
    {"pause", required_argument, NULL, 'z'},
    {"help", no_argument, NULL, 'h'},
    {NULL, 0, NULL, 0}
};

static void print_usage(const char *program)
{
    printf("Uso: %s [opciones] <destino>\n", program);
    printf("  -f, --first-ttl N  TTL inicial (default: %d)\n", DEFAULT_FIRST_TTL);
    printf("  -m, --max-hops N   TTL maximo (default: %d)\n", DEFAULT_MAX_HOPS);
    printf("  -q, --probes N     Probes por salto (default: %d)\n", DEFAULT_PROBES);
    printf("  -w, --timeout S    Espera por probe en segundos (default: %d)\n", DEFAULT_TIMEOUT_SEC);
    printf("  -z, --pause MS     Pausa entre probes (default: %d ms)\n", DEFAULT_PAUSE_MS);
    printf("  -h, --help         Muestra esta ayuda\n");
}

void traceroute_config_defaults(traceroute_config_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->first_ttl = DEFAULT_FIRST_TTL;
    cfg->max_hops = DEFAULT_MAX_HOPS;
    cfg->probes_per_hop = DEFAULT_PROBES;
    cfg->timeout_sec = DEFAULT_TIMEOUT_SEC;
    cfg->pause_ms = DEFAULT_PAUSE_MS;
    cfg->base_dst_port = DEFAULT_BASE_PORT;
    cfg->local_src_port = (uint16_t)(40000 + (getpid() & 0x3FFF));
}

static int parse_integer(const char *text, int minimum, int maximum, int *out)
{
    char *end;
    errno = 0;
    long value = strtol(text, &end, 10);
    if (errno == ERANGE || end == text || *end != '\0' ||
        value < minimum || value > maximum) {
        fprintf(stderr, "Error: valor invalido '%s'; rango %d..%d.\n", text, minimum, maximum);
        return -1;
    }
    *out = (int)value;
    return 0;
}

static int apply_option(int option, const char *text, traceroute_config_t *cfg)
{
    switch (option) {
    case 'f': return parse_integer(text, 1, 255, &cfg->first_ttl);
    case 'm': return parse_integer(text, 1, 255, &cfg->max_hops);
    case 'q': return parse_integer(text, 1, 255, &cfg->probes_per_hop);
    case 'w': return parse_integer(text, 1, INT_MAX / 1000, &cfg->timeout_sec);
    case 'z': return parse_integer(text, 0, INT_MAX, &cfg->pause_ms);
    default: return -1;
    }
}

static int parse_options(int argc, char **argv, traceroute_config_t *cfg)
{
    int option;
    optind = 0;
    opterr = 0;
    while ((option = getopt_long(argc, argv, ":f:m:q:w:z:h", long_options, NULL)) != -1) {
        if (option == 'h') { print_usage(argv[0]); return 1; }
        if (option == '?' || option == ':') {
            fprintf(stderr, "Error: opcion desconocida o sin valor. Use --help.\n");
            return -1;
        }
        if (apply_option(option, optarg, cfg) < 0) return -1;
    }
    return 0;
}

static int read_destination(int argc, char **argv, traceroute_config_t *cfg)
{
    if (argc - optind != 1 || argv[optind][0] == '\0') {
        fprintf(stderr, "Error: se requiere exactamente un destino.\n");
        return -1;
    }
    if (strlen(argv[optind]) >= sizeof(cfg->target_name)) {
        fprintf(stderr, "Error: nombre de destino demasiado largo.\n");
        return -1;
    }
    strcpy(cfg->target_name, argv[optind]);
    return 0;
}

static int validate_configuration(const traceroute_config_t *cfg)
{
    if (cfg->first_ttl > cfg->max_hops) {
        fprintf(stderr, "Error: TTL inicial mayor que TTL maximo.\n");
        return -1;
    }
    unsigned probes = (unsigned)(cfg->max_hops - cfg->first_ttl + 1) *
                      (unsigned)cfg->probes_per_hop;
    if (probes > UINT16_MAX - (unsigned)cfg->base_dst_port + 1U) {
        fprintf(stderr, "Error: demasiados probes para usar puertos UDP unicos.\n");
        return -1;
    }
    return 0;
}

int traceroute_parse_cli(int argc, char **argv, traceroute_config_t *cfg)
{
    traceroute_config_defaults(cfg);
    int status = parse_options(argc, argv, cfg);
    if (status != 0) return status;
    if (read_destination(argc, argv, cfg) < 0) return -1;
    return validate_configuration(cfg);
}
