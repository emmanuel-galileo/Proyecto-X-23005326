#ifndef IP_HEADER_H
#define IP_HEADER_H

#include <stdint.h>

#pragma pack(push, 1)
typedef struct {
    uint8_t  ihl_version;
    uint8_t  tos;
    uint16_t total_length;
    uint16_t id;
    uint16_t flags_fo;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t src_addr;
    uint32_t dst_addr;
} ip_header_t;
#pragma pack(pop)

/* Addresses are in network order; other arguments are in host order. */
void build_ip_header(ip_header_t *iph, uint32_t src, uint32_t dst,
                      uint8_t ttl, uint8_t protocol, uint16_t payload_len,
                      uint16_t id);

#endif
