#include "traceroute_engine.h"
#include "ip_header.h"
#include "udp_header.h"
#include "icmp_parser.h"
#include "raw_socket.h"
#include "dns_resolver.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>

static int init_traceroute_sockets(int timeout_sec, int *send_fd, int *recv_fd)
{
    *send_fd = create_raw_sender_socket();
    if (*send_fd < 0) return -1;

    *recv_fd = create_icmp_receiver_socket(timeout_sec);
    if (*recv_fd < 0) {
        close_socket_fd(*send_fd);
        return -1;
    }
    return 0;
}

static void close_traceroute_sockets(int send_fd, int recv_fd)
{
    close_socket_fd(send_fd);
    close_socket_fd(recv_fd);
}

static void print_traceroute_header(const traceroute_config_t *cfg)
{
    unsigned total_sz = (unsigned)(sizeof(ip_header_t) + sizeof(udp_header_t) + TRACEROUTE_PAYLOAD_SZ);
    printf("traceroute to %s (%s), %u hops max, %u byte packets\n",
           cfg->target_name, cfg->target_ip_str, cfg->max_hops, total_sz);
    fflush(stdout);
}

static size_t assemble_probe_packet(uint8_t *packet, const traceroute_config_t *cfg,
                                    uint8_t ttl, uint16_t dst_port)
{
    ip_header_t *iph = (ip_header_t *)packet;
    udp_header_t *udph = (udp_header_t *)(packet + sizeof(ip_header_t));
    uint8_t *payload = packet + sizeof(ip_header_t) + sizeof(udp_header_t);

    memset(payload, 0x42, TRACEROUTE_PAYLOAD_SZ);
    build_udp_header(udph, cfg->local_src_port, dst_port, TRACEROUTE_PAYLOAD_SZ);
    udph->checksum = calculate_udp_checksum(inet_addr(cfg->local_ip_str),
                                            cfg->target_addr.s_addr,
                                            udph, payload, TRACEROUTE_PAYLOAD_SZ);

    uint16_t ip_payload_len = (uint16_t)(sizeof(udp_header_t) + TRACEROUTE_PAYLOAD_SZ);
    build_ip_header(iph, cfg->local_ip_str, cfg->target_ip_str, ttl, IPPROTO_UDP, ip_payload_len);

    return sizeof(ip_header_t) + ip_payload_len;
}

static int transmit_udp_probe(const traceroute_config_t *cfg, uint8_t ttl,
                              uint16_t dst_port, int send_fd, struct timespec *t_start)
{
    uint8_t packet[128];
    size_t pkt_len = assemble_probe_packet(packet, cfg, ttl, dst_port);
    clock_gettime(CLOCK_MONOTONIC, t_start);
    return send_raw_packet(send_fd, packet, pkt_len, cfg->target_ip_str);
}

static double compute_elapsed_ms(const struct timespec *start, const struct timespec *end)
{
    return (end->tv_sec - start->tv_sec) * 1000.0 + (end->tv_nsec - start->tv_nsec) / 1000000.0;
}

static void record_matching_probe(const icmp_parse_result_t *parsed,
                                  const struct timespec *t_start,
                                  const struct timespec *t_end,
                                  probe_result_t *res)
{
    res->is_timeout = 0;
    res->rtt_ms = compute_elapsed_ms(t_start, t_end);
    res->responder_addr = parsed->responder_ip;
    res->result_type = parsed->result_type;
    inet_ntop(AF_INET, &parsed->responder_ip, res->responder_ip, sizeof(res->responder_ip));
    reverse_dns_lookup(&parsed->responder_ip, res->responder_name, sizeof(res->responder_name));
}

static void await_matching_icmp_response(const traceroute_config_t *cfg, uint16_t dst_port,
                                         int recv_fd, const struct timespec *t_start,
                                         probe_result_t *res)
{
    uint8_t icmp_buf[512];
    struct sockaddr_in from_sa;
    struct timespec t_end, t_now;

    res->is_timeout = 1;
    while (1) {
        int rlen = receive_icmp_packet(recv_fd, icmp_buf, sizeof(icmp_buf), &from_sa);
        if (rlen <= 0) break;

        clock_gettime(CLOCK_MONOTONIC, &t_end);
        icmp_parse_result_t parsed;
        if (parse_and_validate_icmp(icmp_buf, (size_t)rlen, cfg->local_src_port,
                                    dst_port, cfg->target_addr.s_addr, &parsed)) {
            record_matching_probe(&parsed, t_start, &t_end, res);
            break;
        }
        clock_gettime(CLOCK_MONOTONIC, &t_now);
        if (compute_elapsed_ms(t_start, &t_now) >= (cfg->timeout_sec * 1000.0)) break;
    }
}

/* Orquestador que cumple con modularCoding (<= 15 lineas) */
static void execute_single_probe(const traceroute_config_t *cfg, uint8_t ttl,
                                 uint16_t dst_port, int send_fd, int recv_fd,
                                 probe_result_t *res)
{
    struct timespec t_start;
    if (transmit_udp_probe(cfg, ttl, dst_port, send_fd, &t_start) < 0) {
        res->is_timeout = 1;
        return;
    }
    await_matching_icmp_response(cfg, dst_port, recv_fd, &t_start, res);
}

static void print_hop_number(uint8_t ttl)
{
    printf("%2u ", ttl);
    fflush(stdout);
}

static void print_responder_identity(const probe_result_t *res, struct in_addr *last_addr, uint8_t p)
{
    if (res->responder_addr.s_addr != last_addr->s_addr) {
        if (p > 0) printf(" ");
        if (res->responder_name[0] != '\0') {
            printf(" %s (%s)", res->responder_name, res->responder_ip);
        } else {
            printf(" %s (%s)", res->responder_ip, res->responder_ip);
        }
        *last_addr = res->responder_addr;
    }
}

static void print_probe_result(const probe_result_t *res, struct in_addr *last_addr, uint8_t p)
{
    if (res->is_timeout) {
        printf("  *");
    } else {
        print_responder_identity(res, last_addr, p);
        printf("  %.3f ms", res->rtt_ms);
    }
    fflush(stdout);
}

static void sleep_pause_interval(int pause_ms)
{
    if (pause_ms > 0) {
        usleep((useconds_t)pause_ms * 1000);
    }
}

static int is_target_reached(const probe_result_t *res, uint32_t target_ip)
{
    if (res->is_timeout) return 0;
    return (res->result_type == ICMP_RES_TARGET_REACHED ||
            res->responder_addr.s_addr == target_ip);
}

/* Orquestador que cumple con modularCoding (<= 15 lineas) */
static int trace_single_hop(const traceroute_config_t *cfg, uint8_t ttl,
                            uint16_t *current_dst_port, int send_fd, int recv_fd)
{
    struct in_addr last_resp_addr = {0};
    int target_reached = 0;

    print_hop_number(ttl);
    for (uint8_t p = 0; p < cfg->probes_per_hop; p++) {
        probe_result_t res;
        execute_single_probe(cfg, ttl, (*current_dst_port)++, send_fd, recv_fd, &res);
        print_probe_result(&res, &last_resp_addr, p);
        if (is_target_reached(&res, cfg->target_addr.s_addr)) target_reached = 1;
        sleep_pause_interval(cfg->pause_ms);
    }
    printf("\n");
    fflush(stdout);
    return target_reached;
}

/* Orquestador que cumple con modularCoding (<= 15 lineas) */
static void run_hop_loop(const traceroute_config_t *cfg, int send_fd, int recv_fd)
{
    uint16_t current_dst_port = cfg->base_dst_port;
    for (uint8_t ttl = cfg->first_ttl; ttl <= cfg->max_hops; ttl++) {
        int target_reached = trace_single_hop(cfg, ttl, &current_dst_port, send_fd, recv_fd);
        if (target_reached) break;
    }
}

/* Orquestador principal que cumple con modularCoding (<= 15 lineas) */
int traceroute_run(const traceroute_config_t *cfg)
{
    int send_fd = -1, recv_fd = -1;
    if (init_traceroute_sockets(cfg->timeout_sec, &send_fd, &recv_fd) < 0) {
        return -1;
    }
    print_traceroute_header(cfg);
    run_hop_loop(cfg, send_fd, recv_fd);
    close_traceroute_sockets(send_fd, recv_fd);
    return 0;
}
