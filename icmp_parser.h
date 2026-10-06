#ifndef ICMP_PARSER_H
#define ICMP_PARSER_H

#include <stdint.h>
#include <stddef.h>
#include <netinet/in.h>

#define ICMP_TYPE_DEST_UNREACH  3
#define ICMP_TYPE_TIME_EXCEEDED 11
#define ICMP_CODE_PORT_UNREACH  3
#define ICMP_CODE_TTL_EXCEEDED  0

#pragma pack(push, 1)
typedef struct {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint32_t rest_of_header;
} icmp_header_t;
#pragma pack(pop)

typedef enum {
    ICMP_RES_NO_MATCH = 0,
    ICMP_RES_ROUTER_HOP,
    ICMP_RES_TARGET_REACHED,
    ICMP_RES_ERROR_UNREACH
} icmp_result_type_t;

typedef struct {
    icmp_result_type_t result_type;
    struct in_addr responder_ip;
    uint8_t icmp_type;
    uint8_t icmp_code;
} icmp_parse_result_t;

int parse_and_validate_icmp(const uint8_t *packet, size_t size,
                            uint16_t src_port, uint16_t dst_port, uint32_t target,
                            icmp_parse_result_t *result);

#endif
