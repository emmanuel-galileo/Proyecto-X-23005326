#include "checksum.h"
#include "ip_header.h"
#include "udp_header.h"
#include "icmp_parser.h"
#include "traceroute_cli.h"

#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    ip_header_t outer;
    icmp_header_t icmp;
    ip_header_t inner;
    udp_header_t udp;
} test_reply_t;

static void sign_reply(test_reply_t *packet)
{
    packet->outer.checksum = 0;
    packet->icmp.checksum = 0;
    packet->icmp.checksum = htons(calculate_checksum(&packet->icmp,
                                sizeof(*packet) - sizeof(packet->outer)));
    packet->outer.checksum = htons(calculate_checksum(&packet->outer, sizeof(packet->outer)));
}

static test_reply_t make_reply(uint8_t type, uint8_t code, const char *sender)
{
    test_reply_t packet = {0};
    build_ip_header(&packet.outer, inet_addr(sender), inet_addr("192.0.2.1"),
                     64, IPPROTO_ICMP, sizeof(packet) - sizeof(packet.outer), 1);
    build_ip_header(&packet.inner, inet_addr("192.0.2.1"), inet_addr("198.51.100.2"),
                     1, IPPROTO_UDP, 32, 33434);
    build_udp_header(&packet.udp, 40000, 33434, 24);
    packet.icmp.type = type;
    packet.icmp.code = code;
    sign_reply(&packet);
    return packet;
}

static int parse_reply(const test_reply_t *packet, size_t size, icmp_parse_result_t *result)
{
    return parse_and_validate_icmp((const uint8_t *)packet, size, 40000,
                                   33434, inet_addr("198.51.100.2"), result);
}

static void test_checksum_vectors(void)
{
    const uint8_t even[] = {0x00, 0x01, 0xF2, 0x03, 0xF4, 0xF5, 0xF6, 0xF7};
    const uint8_t odd[] = {0x01, 0x23, 0x45};
    uint8_t unaligned[sizeof(even) + 1];
    memcpy(unaligned + 1, even, sizeof(even));
    assert(calculate_checksum(even, sizeof(even)) == 0x220D);
    assert(calculate_checksum(odd, sizeof(odd)) == 0xB9DC);
    assert(calculate_checksum(unaligned + 1, sizeof(even)) == 0x220D);
    assert(calculate_checksum(NULL, 0) == 0xFFFF);
}

static void test_ip_header(void)
{
    ip_header_t header;
    build_ip_header(&header, inet_addr("192.0.2.1"), inet_addr("198.51.100.2"),
                     7, IPPROTO_UDP, 32, 54321);
    assert(sizeof(header) == 20);
    assert(header.ihl_version == 0x45 && header.ttl == 7);
    assert(ntohs(header.total_length) == 52 && ntohs(header.flags_fo) == 0x4000);
    assert(ntohs(header.id) == 54321 && ntohs(header.checksum) == 0xB350);
    assert(calculate_checksum(&header, sizeof(header)) == 0);
}

static void test_udp_checksums(void)
{
    const uint16_t lengths[] = {0, 1, 24, 25, 100};
    const uint16_t expected[] = {0xF4CB, 0xB2C9, 0xD980, 0x977E, 0x0313};
    uint8_t payload[100];
    memset(payload, 0x42, sizeof(payload));
    for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
        udp_header_t header;
        build_udp_header(&header, 40000, 33434, lengths[i]);
        assert(sizeof(header) == 8 && ntohs(header.length) == 8 + lengths[i]);
        assert(calculate_udp_checksum(inet_addr("192.0.2.1"), inet_addr("198.51.100.2"),
                                       &header, payload, lengths[i]) == expected[i]);
    }
}

static void test_udp_zero_checksum(void)
{
    const uint8_t payload[] = {0xF4, 0xC7};
    udp_header_t header;
    build_udp_header(&header, 40000, 33434, sizeof(payload));
    assert(calculate_udp_checksum(inet_addr("192.0.2.1"), inet_addr("198.51.100.2"),
                                   &header, payload, sizeof(payload)) == 0xFFFF);
}

static int parse_numeric_option(const char *flag, const char *value)
{
    traceroute_config_t cfg;
    char *args[] = {"test", (char *)flag, (char *)value, "example.com"};
    return traceroute_parse_cli(4, args, &cfg);
}

static void test_cli_defaults(void)
{
    traceroute_config_t cfg;
    char *args[] = {"test", "example.com"};
    assert(traceroute_parse_cli(2, args, &cfg) == 0);
    assert(cfg.first_ttl == 1 && cfg.max_hops == 64 && cfg.probes_per_hop == 3);
    assert(cfg.timeout_sec == 3 && cfg.pause_ms == 100);
    assert(cfg.base_dst_port == 33434 && cfg.local_src_port != 0);
    assert(strcmp(cfg.target_name, "example.com") == 0);
}

static void test_cli_options(void)
{
    traceroute_config_t cfg;
    char *args[] = {"test", "--first-ttl=2", "--max-hops=10", "--probes=4",
                    "--timeout=1", "--pause=0", "example.com"};
    assert(traceroute_parse_cli(7, args, &cfg) == 0);
    assert(cfg.first_ttl == 2 && cfg.max_hops == 10 && cfg.probes_per_hop == 4);
    assert(cfg.timeout_sec == 1 && cfg.pause_ms == 0);
    assert(parse_numeric_option("-m", "255") == 0);
    assert(parse_numeric_option("-w", "1") == 0);
    assert(parse_numeric_option("-z", "0") == 0);
}

static void test_cli_invalid_numbers(void)
{
    assert(parse_numeric_option("-f", "abc") == -1);
    assert(parse_numeric_option("-m", "256") == -1);
    assert(parse_numeric_option("-q", "0") == -1);
    assert(parse_numeric_option("-q", "256") == -1);
    assert(parse_numeric_option("-w", "0") == -1);
    assert(parse_numeric_option("-w", "2147483647") == -1);
    assert(parse_numeric_option("-z", "-1") == -1);
    assert(parse_numeric_option("-q", "3junk") == -1);
    assert(parse_numeric_option("-q", "999999999999999999999999") == -1);
    assert(parse_numeric_option("-f", "65") == -1);
}

static void test_cli_structure(void)
{
    traceroute_config_t cfg;
    char *missing[] = {"test"};
    char *multiple[] = {"test", "first", "second"};
    char *no_value[] = {"test", "-m"};
    char *unknown[] = {"test", "--unknown", "example.com"};
    char *excessive[] = {"test", "-m", "255", "-q", "255", "example.com"};
    assert(traceroute_parse_cli(1, missing, &cfg) == -1);
    assert(traceroute_parse_cli(3, multiple, &cfg) == -1);
    assert(traceroute_parse_cli(2, no_value, &cfg) == -1);
    assert(traceroute_parse_cli(3, unknown, &cfg) == -1);
    assert(traceroute_parse_cli(6, excessive, &cfg) == -1);
}

static void test_icmp_classification(void)
{
    icmp_parse_result_t result;
    test_reply_t hop = make_reply(11, 0, "203.0.113.1");
    test_reply_t target = make_reply(3, 3, "198.51.100.2");
    test_reply_t blocked = make_reply(3, 3, "203.0.113.1");
    assert(parse_reply(&hop, sizeof(hop), &result) && result.result_type == ICMP_RES_ROUTER_HOP);
    assert(parse_reply(&target, sizeof(target), &result) && result.result_type == ICMP_RES_TARGET_REACHED);
    assert(parse_reply(&blocked, sizeof(blocked), &result) && result.result_type == ICMP_RES_ERROR_UNREACH);
    hop = make_reply(11, 1, "203.0.113.1");
    assert(!parse_reply(&hop, sizeof(hop), &result));
    hop = make_reply(5, 0, "203.0.113.1");
    assert(!parse_reply(&hop, sizeof(hop), &result));
}

static void test_icmp_correlation(void)
{
    icmp_parse_result_t result;
    test_reply_t packet = make_reply(11, 0, "203.0.113.1");
    packet.udp.src_port = htons(40001);
    sign_reply(&packet);
    assert(!parse_reply(&packet, sizeof(packet), &result));
    packet = make_reply(11, 0, "203.0.113.1");
    packet.udp.dst_port = htons(33435);
    sign_reply(&packet);
    assert(!parse_reply(&packet, sizeof(packet), &result));
    packet = make_reply(11, 0, "203.0.113.1");
    packet.inner.dst_addr = inet_addr("198.51.100.3");
    sign_reply(&packet);
    assert(!parse_reply(&packet, sizeof(packet), &result));
}

static void test_icmp_malformed_headers(void)
{
    icmp_parse_result_t result;
    test_reply_t packet = make_reply(11, 0, "203.0.113.1");
    packet.outer.ihl_version = 0x65;
    sign_reply(&packet);
    assert(!parse_reply(&packet, sizeof(packet), &result));
    packet = make_reply(11, 0, "203.0.113.1");
    packet.inner.ihl_version = 0x44;
    sign_reply(&packet);
    assert(!parse_reply(&packet, sizeof(packet), &result));
    packet = make_reply(11, 0, "203.0.113.1");
    assert(!parse_reply(&packet, sizeof(packet) - 1, &result));
    packet.icmp.checksum ^= 1;
    assert(!parse_reply(&packet, sizeof(packet), &result));
}

int main(void)
{
    test_checksum_vectors();
    test_ip_header();
    test_udp_checksums();
    test_udp_zero_checksum();
    test_cli_defaults();
    test_cli_options();
    test_cli_invalid_numbers();
    test_cli_structure();
    test_icmp_classification();
    test_icmp_correlation();
    test_icmp_malformed_headers();
    puts("core: passed");
    return 0;
}
