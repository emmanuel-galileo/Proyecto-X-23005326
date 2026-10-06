#ifndef UDP_HEADER_H
#define UDP_HEADER_H

#include <stdint.h>

#pragma pack(push, 1)
typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
} udp_header_t;
#pragma pack(pop)

void build_udp_header(udp_header_t *udph, uint16_t src_port,
                       uint16_t dst_port, uint16_t payload_len);
/* Returns a host-order checksum; src and dst are network-order addresses. */
uint16_t calculate_udp_checksum(uint32_t src, uint32_t dst,
                                 const udp_header_t *udph,
                                 const uint8_t *payload, uint16_t payload_len);

#endif
