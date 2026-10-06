#include "icmp_parser.h"
#include "ip_header.h"
#include "udp_header.h"
#include "checksum.h"

#include <string.h>
#include <arpa/inet.h>

typedef struct {
    ip_header_t outer;
    icmp_header_t icmp;
    ip_header_t inner;
    udp_header_t udp;
} reply_headers_t;

static int read_ip_header(const uint8_t *packet, size_t size, uint8_t protocol,
                           ip_header_t *header, size_t *header_size)
{
    if (size < sizeof(*header)) return 0;
    memcpy(header, packet, sizeof(*header));
    *header_size = (size_t)(header->ihl_version & 0x0F) * 4;
    return (header->ihl_version >> 4) == 4 && *header_size >= sizeof(*header) &&
           *header_size <= size && header->protocol == protocol &&
           ntohs(header->total_length) >= *header_size;
}

static int read_outer_headers(const uint8_t *packet, size_t *size,
                               reply_headers_t *headers, size_t *ip_size)
{
    if (!read_ip_header(packet, *size, IPPROTO_ICMP, &headers->outer, ip_size)) return 0;
    size_t total = ntohs(headers->outer.total_length);
    if (total > *size || total < *ip_size + sizeof(headers->icmp)) return 0;
    if ((ntohs(headers->outer.flags_fo) & 0x3FFF) != 0) return 0;
    if (calculate_checksum(packet, *ip_size) != 0 ||
        calculate_checksum(packet + *ip_size, total - *ip_size) != 0) return 0;
    memcpy(&headers->icmp, packet + *ip_size, sizeof(headers->icmp));
    *size = total;
    return 1;
}

static int read_quoted_headers(const uint8_t *packet, size_t size,
                                reply_headers_t *headers)
{
    size_t ip_size;
    if (!read_ip_header(packet, size, IPPROTO_UDP, &headers->inner, &ip_size)) return 0;
    if (size < ip_size + sizeof(headers->udp) ||
        ntohs(headers->inner.total_length) < ip_size + sizeof(headers->udp)) return 0;
    if ((ntohs(headers->inner.flags_fo) & 0x1FFF) != 0) return 0;
    memcpy(&headers->udp, packet + ip_size, sizeof(headers->udp));
    return ntohs(headers->udp.length) >= sizeof(headers->udp);
}

static int matches_probe(const reply_headers_t *headers, uint16_t src_port,
                           uint16_t dst_port, uint32_t target)
{
    return ntohs(headers->udp.src_port) == src_port &&
           ntohs(headers->udp.dst_port) == dst_port &&
           headers->inner.dst_addr == target;
}

static icmp_result_type_t classify_reply(const reply_headers_t *headers, uint32_t target)
{
    if (headers->icmp.type == ICMP_TYPE_TIME_EXCEEDED &&
        headers->icmp.code == ICMP_CODE_TTL_EXCEEDED) return ICMP_RES_ROUTER_HOP;
    if (headers->icmp.type != ICMP_TYPE_DEST_UNREACH || headers->icmp.code > 15)
        return ICMP_RES_NO_MATCH;
    if (headers->icmp.code == ICMP_CODE_PORT_UNREACH && headers->outer.src_addr == target)
        return ICMP_RES_TARGET_REACHED;
    return ICMP_RES_ERROR_UNREACH;
}

static void fill_result(const reply_headers_t *headers, icmp_result_type_t type,
                         icmp_parse_result_t *result)
{
    result->responder_ip.s_addr = headers->outer.src_addr;
    result->icmp_type = headers->icmp.type;
    result->icmp_code = headers->icmp.code;
    result->result_type = type;
}

int parse_and_validate_icmp(const uint8_t *packet, size_t size,
                            uint16_t src_port, uint16_t dst_port, uint32_t target,
                            icmp_parse_result_t *result)
{
    reply_headers_t headers;
    size_t ip_size;
    if (!packet || !result || !read_outer_headers(packet, &size, &headers, &ip_size)) return 0;
    icmp_result_type_t type = classify_reply(&headers, target);
    if (type == ICMP_RES_NO_MATCH) return 0;
    size_t offset = ip_size + sizeof(headers.icmp);
    if (!read_quoted_headers(packet + offset, size - offset, &headers)) return 0;
    if (!matches_probe(&headers, src_port, dst_port, target)) return 0;
    fill_result(&headers, type, result);
    return 1;
}
