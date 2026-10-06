#include "traceroute_engine.h"
#include "raw_socket.h"
#include "dns_resolver.h"
#include "ip_header.h"
#include "udp_header.h"
#include "checksum.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

enum scenario {
    TIMEOUTS, ARRIVE_AT_SECOND_HOP, ROUTER_PORT_UNREACHABLE,
    TARGET_OTHER_UNREACHABLE, FOREIGN_THEN_LATE, SEND_FAILURE,
    RECEIVE_FAILURE, OPEN_FAILURE, PAUSE_INTERRUPTED
};

static enum scenario scenario;
static int sends, receives, pauses, closes, dns_queries, last_ttl;
static struct timespec now, probe_start;
static unsigned last_port;
static uint8_t outgoing[52];
static char captured[32768];

typedef struct {
    ip_header_t outer;
    icmp_header_t icmp;
    ip_header_t inner;
    udp_header_t udp;
} test_reply_t;

static traceroute_config_t setup(enum scenario selected)
{
    traceroute_config_t cfg = {0};
    scenario = selected;
    sends = receives = pauses = closes = dns_queries = last_ttl = 0;
    now = (struct timespec){0};
    last_port = 0;
    cfg.first_ttl = 1; cfg.max_hops = 3; cfg.probes_per_hop = 3;
    cfg.timeout_sec = 3; cfg.pause_ms = 100;
    cfg.base_dst_port = 33434; cfg.local_src_port = 40000;
    cfg.local_addr.s_addr = inet_addr("192.0.2.1");
    cfg.target_addr.s_addr = inet_addr("198.51.100.2");
    strcpy(cfg.target_name, "target.test"); strcpy(cfg.target_ip_str, "198.51.100.2");
    return cfg;
}

int clock_gettime(clockid_t clock, struct timespec *result)
{
    assert(clock == CLOCK_MONOTONIC);
    *result = now;
    return 0;
}

int nanosleep(const struct timespec *requested, struct timespec *remaining)
{
    assert(requested->tv_sec == 0);
    assert(requested->tv_nsec == 100000000L || requested->tv_nsec == 50000000L);
    pauses++;
    if (scenario == PAUSE_INTERRUPTED && pauses == 1) {
        *remaining = (struct timespec){0, 50000000L};
        errno = EINTR;
        return -1;
    }
    return 0;
}

int create_raw_sender_socket(void) { return 10; }

int create_icmp_receiver_socket(void)
{
    if (scenario == OPEN_FAILURE) { errno = EPERM; return -1; }
    return 11;
}

void close_socket_fd(int fd)
{
    if (fd >= 0) { assert(fd == 10 || fd == 11); closes++; }
}

static void validate_outgoing_packet(const uint8_t *data, size_t size)
{
    ip_header_t ip;
    udp_header_t udp;
    assert(size == sizeof(outgoing));
    memcpy(&ip, data, sizeof(ip)); memcpy(&udp, data + sizeof(ip), sizeof(udp));
    assert(calculate_checksum(data, sizeof(ip)) == 0 && ip.protocol == IPPROTO_UDP);
    assert(ntohs(ip.total_length) == 52 && ntohs(udp.length) == 32);
    assert(ntohs(udp.dst_port) == 33434 + sends);
    assert(ntohs(udp.checksum) == calculate_udp_checksum(ip.src_addr, ip.dst_addr,
                                                        &udp, data + 28, 24));
    last_ttl = ip.ttl;
    last_port = ntohs(udp.dst_port);
}

int send_raw_packet(int fd, const uint8_t *data, size_t size, const struct in_addr *target)
{
    assert(fd == 10 && target->s_addr == inet_addr("198.51.100.2"));
    validate_outgoing_packet(data, size);
    memcpy(outgoing, data, size);
    sends++;
    receives = 0;
    probe_start = now;
    if (scenario == SEND_FAILURE) { errno = EACCES; return -1; }
    return 0;
}

static test_reply_t make_response(void)
{
    test_reply_t packet = {0};
    uint32_t sender = inet_addr("203.0.113.1");
    packet.icmp.type = 11;
    if (scenario == ARRIVE_AT_SECOND_HOP && last_ttl == 2) {
        sender = inet_addr("198.51.100.2"); packet.icmp.type = 3; packet.icmp.code = 3;
    }
    if (scenario == ROUTER_PORT_UNREACHABLE) { packet.icmp.type = 3; packet.icmp.code = 3; }
    if (scenario == TARGET_OTHER_UNREACHABLE) {
        sender = inet_addr("198.51.100.2"); packet.icmp.type = 3; packet.icmp.code = 13;
    }
    build_ip_header(&packet.outer, sender, inet_addr("192.0.2.1"), 64, IPPROTO_ICMP, 36, 1);
    memcpy(&packet.inner, outgoing, sizeof(packet.inner));
    memcpy(&packet.udp, outgoing + sizeof(packet.inner), sizeof(packet.udp));
    return packet;
}

static int fill_response(uint8_t *buffer, size_t capacity)
{
    test_reply_t packet = make_response();
    assert(capacity >= sizeof(packet));
    if (scenario == FOREIGN_THEN_LATE && receives == 1)
        packet.udp.dst_port = htons((uint16_t)(last_port + 1));
    packet.icmp.checksum = htons(calculate_checksum(&packet.icmp, 36));
    memcpy(buffer, &packet, sizeof(packet));
    return sizeof(packet);
}

int receive_icmp_packet(int fd, uint8_t *buffer, size_t capacity,
                        const struct timespec *deadline)
{
    assert(fd == 11 && deadline->tv_sec == probe_start.tv_sec + 3);
    assert(deadline->tv_nsec == probe_start.tv_nsec);
    receives++;
    if (scenario == TIMEOUTS || scenario == PAUSE_INTERRUPTED) { now = *deadline; return 0; }
    if (scenario == RECEIVE_FAILURE) { errno = EIO; return -1; }
    now = probe_start;
    now.tv_nsec += 50000000L;
    if (scenario == FOREIGN_THEN_LATE) {
        now.tv_sec += receives == 1 ? 2 : 5;
        now.tv_nsec = receives == 1 ? 900000000L : 800000000L;
    }
    return fill_response(buffer, capacity);
}

int reverse_dns_lookup(const struct in_addr *addr, char *hostname, size_t size)
{
    dns_queries++;
    snprintf(hostname, size, "%s", addr->s_addr == inet_addr("198.51.100.2") ?
                                  "target.test" : "router.test");
    return 1;
}

static FILE *capture_output(int *original)
{
    FILE *file = tmpfile();
    assert(file != NULL);
    fflush(stdout);
    *original = dup(fileno(stdout));
    assert(*original >= 0 && dup2(fileno(file), fileno(stdout)) >= 0);
    return file;
}

static void finish_capture(FILE *file, int original)
{
    fflush(stdout);
    assert(dup2(original, fileno(stdout)) >= 0);
    close(original);
    rewind(file);
    size_t length = fread(captured, 1, sizeof(captured) - 1, file);
    captured[length] = '\0';
    fclose(file);
}

static int run_trace(traceroute_config_t *cfg)
{
    int original;
    FILE *file = capture_output(&original);
    int status = traceroute_run(cfg);
    finish_capture(file, original);
    return status;
}

static void test_arrival_and_output(void)
{
    traceroute_config_t cfg = setup(ARRIVE_AT_SECOND_HOP);
    assert(run_trace(&cfg) == 0);
    assert(sends == 6 && last_ttl == 2 && pauses == 5 && closes == 2);
    assert(dns_queries == 2);
    assert(strstr(captured, "52 byte packets") != NULL);
    assert(strstr(captured, "router.test (203.0.113.1)") != NULL);
    assert(strstr(captured, "target.test (198.51.100.2)") != NULL);
    assert(strstr(captured, "50.000 ms") != NULL);
}

static void test_unreachable_is_not_arrival(void)
{
    traceroute_config_t cfg = setup(ROUTER_PORT_UNREACHABLE);
    assert(run_trace(&cfg) == 0 && sends == 9 && last_ttl == 3 && closes == 2);
    assert(strstr(captured, "!unreachable(3)") != NULL);
    cfg = setup(TARGET_OTHER_UNREACHABLE);
    assert(run_trace(&cfg) == 0 && sends == 9 && last_ttl == 3 && closes == 2);
    assert(strstr(captured, "!unreachable(13)") != NULL);
}

static void test_timeout_and_ttl_limit(void)
{
    traceroute_config_t cfg = setup(TIMEOUTS);
    cfg.max_hops = 255; cfg.probes_per_hop = 1;
    assert(run_trace(&cfg) == 0 && sends == 255 && last_ttl == 255 && closes == 2);
    assert(pauses == 254 && dns_queries == 0);
    assert(strstr(captured, "255   *") != NULL);
}

static void test_late_response(void)
{
    traceroute_config_t cfg = setup(FOREIGN_THEN_LATE);
    cfg.max_hops = 1; cfg.probes_per_hop = 1;
    assert(run_trace(&cfg) == 0 && sends == 1 && receives == 2 && closes == 2);
    assert(strstr(captured, "  *") != NULL && strstr(captured, " ms") == NULL);
    assert(dns_queries == 0);
}

static void test_errors_close_sockets(void)
{
    traceroute_config_t cfg = setup(SEND_FAILURE);
    assert(run_trace(&cfg) == 1 && sends == 1 && closes == 2);
    assert(strstr(captured, "  *") == NULL);
    cfg = setup(RECEIVE_FAILURE);
    assert(run_trace(&cfg) == 1 && sends == 1 && closes == 2);
    cfg = setup(OPEN_FAILURE);
    assert(run_trace(&cfg) == 1 && sends == 0 && closes == 1);
}

static void test_pause_interruption(void)
{
    traceroute_config_t cfg = setup(PAUSE_INTERRUPTED);
    cfg.max_hops = 1;
    assert(run_trace(&cfg) == 0 && sends == 3 && pauses == 3 && closes == 2);
}

int main(void)
{
    test_arrival_and_output();
    test_unreachable_is_not_arrival();
    test_timeout_and_ttl_limit();
    test_late_response();
    test_errors_close_sockets();
    test_pause_interruption();
    puts("engine regressions: passed");
    return 0;
}
