#include "traceroute_output.h"
#include "dns_resolver.h"
#include "ip_header.h"
#include "udp_header.h"

#include <stdio.h>
#include <string.h>

void print_traceroute_header(const traceroute_config_t *cfg)
{
    size_t size = sizeof(ip_header_t) + sizeof(udp_header_t) + TRACEROUTE_PAYLOAD_SZ;
    printf("traceroute to %s (%s), %d hops max, %zu byte packets\n",
           cfg->target_name, cfg->target_ip_str, cfg->max_hops, size);
    fflush(stdout);
}

void print_hop_begin(int ttl, hop_output_t *output)
{
    memset(output, 0, sizeof(*output));
    printf("%2d ", ttl);
    fflush(stdout);
}

static void print_responder(const struct in_addr *addr, hop_output_t *output)
{
    char ip[INET_ADDRSTRLEN];
    char hostname[256] = {0};
    if (output->has_addr && output->last_addr.s_addr == addr->s_addr) return;
    inet_ntop(AF_INET, addr, ip, sizeof(ip));
    reverse_dns_lookup(addr, hostname, sizeof(hostname));
    printf(" %s (%s)", hostname[0] ? hostname : ip, ip);
    output->last_addr = *addr;
    output->has_addr = 1;
}

void print_probe_result(const probe_result_t *result, hop_output_t *output)
{
    if (result->is_timeout) {
        printf("  *");
    } else {
        print_responder(&result->responder_addr, output);
        printf("  %.3f ms", result->rtt_ms);
        if (result->result_type == ICMP_RES_ERROR_UNREACH)
            printf(" !unreachable(%u)", result->icmp_code);
    }
    fflush(stdout);
}

void print_hop_end(void)
{
    printf("\n");
    fflush(stdout);
}
