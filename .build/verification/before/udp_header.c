#include "udp_header.h"
#include "checksum.h"

#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#pragma pack(push, 1)
typedef struct {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint8_t  zero;
    uint8_t  protocol;
    uint16_t udp_length;
} udp_pseudo_header_t;
#pragma pack(pop)

/* Orquestador que cumple con modularCoding (<= 15 lineas) */
void build_udp_header(udp_header_t *udph, uint16_t src_port, uint16_t dst_port,
                       uint16_t payload_len)
{
    memset(udph, 0, sizeof(udp_header_t));
    udph->src_port = htons(src_port);
    udph->dst_port = htons(dst_port);
    udph->length   = htons((uint16_t)(sizeof(udp_header_t) + payload_len));
    udph->checksum = 0;
}

static void fill_pseudo_header(udp_pseudo_header_t *psh, uint32_t src, uint32_t dst, uint16_t udp_len)
{
    psh->src_addr   = src;
    psh->dst_addr   = dst;
    psh->zero       = 0;
    psh->protocol   = IPPROTO_UDP;
    psh->udp_length = htons(udp_len);
}

static uint8_t *allocate_udp_pseudo_packet(size_t total_len, const udp_pseudo_header_t *psh,
                                           const udp_header_t *udph,
                                           const uint8_t *payload, uint16_t payload_len)
{
    uint8_t *buf = malloc(total_len);
    if (!buf) return NULL;

    memcpy(buf, psh, sizeof(udp_pseudo_header_t));
    memcpy(buf + sizeof(udp_pseudo_header_t), udph, sizeof(udp_header_t));
    if (payload && payload_len > 0) {
        memcpy(buf + sizeof(udp_pseudo_header_t) + sizeof(udp_header_t), payload, payload_len);
    }
    return buf;
}

static uint16_t normalize_udp_checksum(uint16_t sum)
{
    return (sum == 0) ? 0xFFFF : sum;
}

/* Orquestador que cumple con modularCoding (<= 15 lineas) */
uint16_t calculate_udp_checksum(uint32_t src_addr, uint32_t dst_addr,
                                 const udp_header_t *udph,
                                 const uint8_t *payload, uint16_t payload_len)
{
    uint16_t udp_len = (uint16_t)(sizeof(udp_header_t) + payload_len);
    size_t total_len = sizeof(udp_pseudo_header_t) + udp_len;
    udp_pseudo_header_t psh;

    fill_pseudo_header(&psh, src_addr, dst_addr, udp_len);
    uint8_t *buf = allocate_udp_pseudo_packet(total_len, &psh, udph, payload, payload_len);
    if (!buf) return 0;

    uint16_t sum = calculate_checksum((const uint16_t *)buf, (int)total_len);
    free(buf);
    return normalize_udp_checksum(sum);
}
