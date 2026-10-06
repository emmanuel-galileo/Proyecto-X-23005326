#include "ip_header.h"
#include "checksum.h"

#include <string.h>
#include <arpa/inet.h>

static void set_ip_format(ip_header_t *iph, uint16_t payload_len)
{
    iph->ihl_version = 0x45;
    iph->total_length = htons((uint16_t)(sizeof(*iph) + payload_len));
    iph->flags_fo = htons(0x4000);
}

static void set_ip_route(ip_header_t *iph, uint32_t src, uint32_t dst,
                         uint8_t ttl, uint8_t protocol, uint16_t id)
{
    iph->src_addr = src;
    iph->dst_addr = dst;
    iph->ttl = ttl;
    iph->protocol = protocol;
    iph->id = htons(id);
}

void build_ip_header(ip_header_t *iph, uint32_t src, uint32_t dst,
                      uint8_t ttl, uint8_t protocol, uint16_t payload_len,
                      uint16_t id)
{
    memset(iph, 0, sizeof(*iph));
    set_ip_format(iph, payload_len);
    set_ip_route(iph, src, dst, ttl, protocol, id);
    iph->checksum = htons(calculate_checksum(iph, sizeof(*iph)));
}
