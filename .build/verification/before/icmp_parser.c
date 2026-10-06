#include "icmp_parser.h"
#include "ip_header.h"
#include "udp_header.h"

#include <string.h>
#include <arpa/inet.h>

static int validate_outer_ip(const uint8_t *pkt, size_t len, int *out_ip_len)
{
    if (len < sizeof(ip_header_t) + sizeof(icmp_header_t)) return 0;
    const ip_header_t *iph = (const ip_header_t *)pkt;
    if (iph->protocol != IPPROTO_ICMP) return 0;

    int ip_len = (iph->ihl_version & 0x0F) * 4;
    if (len < (size_t)ip_len + sizeof(icmp_header_t)) return 0;
    *out_ip_len = ip_len;
    return 1;
}

static int validate_inner_packet(const uint8_t *pkt, size_t len, int outer_ip_len, int *out_inner_ip_len)
{
    size_t min_needed = (size_t)outer_ip_len + sizeof(icmp_header_t) + sizeof(ip_header_t) + sizeof(udp_header_t);
    if (len < min_needed) return 0;

    const ip_header_t *inner_iph = (const ip_header_t *)(pkt + outer_ip_len + sizeof(icmp_header_t));
    if (inner_iph->protocol != IPPROTO_UDP) return 0;

    int inner_ip_len = (inner_iph->ihl_version & 0x0F) * 4;
    if (len < (size_t)outer_ip_len + sizeof(icmp_header_t) + (size_t)inner_ip_len + sizeof(udp_header_t)) return 0;

    *out_inner_ip_len = inner_ip_len;
    return 1;
}

static int match_inner_udp(const uint8_t *pkt, int udp_offset, uint16_t expected_src, uint16_t expected_dst)
{
    const udp_header_t *inner_udph = (const udp_header_t *)(pkt + udp_offset);
    uint16_t actual_src = ntohs(inner_udph->src_port);
    uint16_t actual_dst = ntohs(inner_udph->dst_port);

    if (expected_src != 0 && actual_src != expected_src) return 0;
    if (expected_dst != 0 && actual_dst != expected_dst) return 0;
    return 1;
}

static int match_inner_ip_dst(const uint8_t *pkt, int inner_ip_offset, uint32_t expected_target)
{
    if (expected_target == 0) return 1;
    const ip_header_t *inner_iph = (const ip_header_t *)(pkt + inner_ip_offset);
    return (inner_iph->dst_addr == expected_target);
}

static icmp_result_type_t classify_icmp_type_code(uint8_t type, uint8_t code)
{
    if (type == ICMP_TYPE_TIME_EXCEEDED) return ICMP_RES_ROUTER_HOP;
    if (type == ICMP_TYPE_DEST_UNREACH) {
        return (code == ICMP_CODE_PORT_UNREACH) ? ICMP_RES_TARGET_REACHED : ICMP_RES_ERROR_UNREACH;
    }
    return ICMP_RES_NO_MATCH;
}

static void extract_and_fill_result(const uint8_t *raw_pkt, int outer_ip_len, icmp_parse_result_t *result)
{
    const ip_header_t *outer_iph = (const ip_header_t *)raw_pkt;
    const icmp_header_t *icmph = (const icmp_header_t *)(raw_pkt + outer_ip_len);

    result->responder_ip.s_addr = outer_iph->src_addr;
    result->icmp_type = icmph->type;
    result->icmp_code = icmph->code;
    result->result_type = classify_icmp_type_code(icmph->type, icmph->code);
}

/* Orquestador que cumple con modularCoding (<= 15 lineas) */
int parse_and_validate_icmp(const uint8_t *raw_pkt, size_t pkt_len,
                            uint16_t expected_src_port, uint16_t expected_dst_port,
                            uint32_t expected_target_ip,
                            icmp_parse_result_t *result)
{
    int outer_ip_len = 0, inner_ip_len = 0;
    if (!validate_outer_ip(raw_pkt, pkt_len, &outer_ip_len)) return 0;
    if (!validate_inner_packet(raw_pkt, pkt_len, outer_ip_len, &inner_ip_len)) return 0;

    int inner_ip_offset = outer_ip_len + (int)sizeof(icmp_header_t);
    int udp_offset = inner_ip_offset + inner_ip_len;

    if (!match_inner_udp(raw_pkt, udp_offset, expected_src_port, expected_dst_port)) return 0;
    if (!match_inner_ip_dst(raw_pkt, inner_ip_offset, expected_target_ip)) return 0;

    extract_and_fill_result(raw_pkt, outer_ip_len, result);
    return 1;
}
