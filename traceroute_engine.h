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
    int first_ttl;
    int max_hops;
    int probes_per_hop;
    int timeout_sec;
    int pause_ms;
    uint16_t base_dst_port;
    uint16_t local_src_port;
    char target_name[256];
    char target_ip_str[INET_ADDRSTRLEN];
    struct in_addr target_addr;
    struct in_addr local_addr;
} traceroute_config_t;

typedef struct {
    int is_timeout;
    double rtt_ms;
    struct in_addr responder_addr;
    icmp_result_type_t result_type;
    uint8_t icmp_code;
} probe_result_t;

int traceroute_run(const traceroute_config_t *cfg);

#endif
