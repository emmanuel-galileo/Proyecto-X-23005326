#ifndef TRACEROUTE_ENGINE_H
#define TRACEROUTE_ENGINE_H

#include <stdint.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "icmp_parser.h"

#define DEFAULT_FIRST_TTL     1
#define DEFAULT_MAX_HOPS      64
#define DEFAULT_PROBES        3
#define DEFAULT_TIMEOUT_SEC   3
#define DEFAULT_PAUSE_MS      100
#define DEFAULT_BASE_PORT     33434
#define TRACEROUTE_PAYLOAD_SZ 24

typedef struct {
    uint8_t        first_ttl;
    uint8_t        max_hops;
    uint8_t        probes_per_hop;
    int            timeout_sec;
    int            pause_ms;
    uint16_t       base_dst_port;
    uint16_t       local_src_port;
    char           target_name[256];
    char           target_ip_str[INET_ADDRSTRLEN];
    struct in_addr target_addr;
    char           local_ip_str[INET_ADDRSTRLEN];
} traceroute_config_t;

typedef struct {
    int                is_timeout;
    double             rtt_ms;
    struct in_addr     responder_addr;
    char               responder_ip[INET_ADDRSTRLEN];
    char               responder_name[256];
    icmp_result_type_t result_type;
} probe_result_t;

/*
 * Orquestador principal que ejecuta la traza completa de saltos.
 */
int traceroute_run(const traceroute_config_t *cfg);

#endif /* TRACEROUTE_ENGINE_H */
