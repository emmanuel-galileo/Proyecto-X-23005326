#include "udp_header.h"
#include "checksum.h"

#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#pragma pack(push, 1)
typedef struct {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint8_t zero;
    uint8_t protocol;
    uint16_t udp_length;
} udp_pseudo_header_t;
#pragma pack(pop)

void build_udp_header(udp_header_t *udph, uint16_t src_port,
                       uint16_t dst_port, uint16_t payload_len)
{
    memset(udph, 0, sizeof(*udph));
    udph->src_port = htons(src_port);
    udph->dst_port = htons(dst_port);
    udph->length = htons((uint16_t)(sizeof(*udph) + payload_len));
}

static udp_pseudo_header_t make_pseudo_header(uint32_t src, uint32_t dst,
                                              uint16_t udp_length)
{
    udp_pseudo_header_t header = {src, dst, 0, IPPROTO_UDP, htons(udp_length)};
    return header;
}

uint16_t calculate_udp_checksum(uint32_t src, uint32_t dst,
                                 const udp_header_t *udph,
                                 const uint8_t *payload, uint16_t payload_len)
{
    udp_pseudo_header_t pseudo = make_pseudo_header(src, dst,
                                    (uint16_t)(sizeof(*udph) + payload_len));
    udp_header_t header = *udph;
    header.checksum = 0;
    uint32_t sum = checksum_accumulate(0, &pseudo, sizeof(pseudo));
    sum = checksum_accumulate(sum, &header, sizeof(header));
    sum = checksum_accumulate(sum, payload, payload_len);
    uint16_t checksum = checksum_finish(sum);
    return checksum == 0 ? 0xFFFF : checksum;
}
