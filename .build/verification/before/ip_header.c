#include "ip_header.h"
#include "checksum.h"

#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>

static uint16_t ip_id_counter = 54321;

static void set_ip_format_and_tos(ip_header_t *iph)
{
    iph->ihl_version = (4 << 4) | 5; /* IPv4, 5 palabras de 32 bits = 20 bytes */
    iph->tos = 0;
}

static void set_ip_length_and_flags(ip_header_t *iph, uint16_t payload_len)
{
    uint16_t total = (uint16_t)(sizeof(ip_header_t) + payload_len);
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    iph->total_length = total;
    iph->flags_fo      = 0x4000; /* Don't Fragment en host byte order */
#else
    iph->total_length = htons(total);
    iph->flags_fo      = htons(0x4000); /* Don't Fragment en network byte order */
#endif
}

static void set_ip_control_fields(ip_header_t *iph, uint8_t ttl, uint8_t protocol)
{
    iph->id       = htons(ip_id_counter++);
    iph->ttl      = ttl;
    iph->protocol = protocol;
    iph->checksum = 0;
}

static void set_ip_addresses(ip_header_t *iph, const char *src_ip, const char *dst_ip)
{
    iph->src_addr = (src_ip && strlen(src_ip) > 0) ? inet_addr(src_ip) : (uint32_t)INADDR_ANY;
    iph->dst_addr = inet_addr(dst_ip);
}

/* Orquestador que cumple con modularCoding (<= 15 lineas) */
void build_ip_header(ip_header_t *iph, const char *src_ip, const char *dst_ip,
                      uint8_t ttl, uint8_t protocol, uint16_t payload_len)
{
    memset(iph, 0, sizeof(ip_header_t));
    set_ip_format_and_tos(iph);
    set_ip_length_and_flags(iph, payload_len);
    set_ip_control_fields(iph, ttl, protocol);
    set_ip_addresses(iph, src_ip, dst_ip);
    iph->checksum = calculate_checksum((const uint16_t *)iph, (int)sizeof(ip_header_t));
}