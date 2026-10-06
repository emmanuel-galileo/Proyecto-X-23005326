#include "traceroute_engine.h"
#include "traceroute_output.h"
#include "ip_header.h"
#include "udp_header.h"
#include "raw_socket.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

typedef struct {
    int send_fd;
    int recv_fd;
    unsigned next_port;
    unsigned sent_probes;
} trace_context_t;

typedef struct {
    ip_header_t ip;
    udp_header_t udp;
    uint8_t payload[TRACEROUTE_PAYLOAD_SZ];
} probe_packet_t;

static void close_trace_sockets(const trace_context_t *context)
{
    close_socket_fd(context->send_fd);
    close_socket_fd(context->recv_fd);
}

static int open_trace_sockets(trace_context_t *context)
{
    context->send_fd = create_raw_sender_socket();
    if (context->send_fd < 0) return -1;
    context->recv_fd = create_icmp_receiver_socket();
    if (context->recv_fd < 0) { close_trace_sockets(context); return -1; }
    return 0;
}

static void build_probe_udp(probe_packet_t *packet, const traceroute_config_t *cfg,
                             uint16_t port)
{
    memset(packet->payload, 0x42, sizeof(packet->payload));
    build_udp_header(&packet->udp, cfg->local_src_port, port, sizeof(packet->payload));
    packet->udp.checksum = htons(calculate_udp_checksum(cfg->local_addr.s_addr,
                                cfg->target_addr.s_addr, &packet->udp,
                                packet->payload, sizeof(packet->payload)));
}

static void build_probe_packet(probe_packet_t *packet, const traceroute_config_t *cfg,
                                int ttl, uint16_t port)
{
    build_probe_udp(packet, cfg, port);
    build_ip_header(&packet->ip, cfg->local_addr.s_addr, cfg->target_addr.s_addr,
                    (uint8_t)ttl, IPPROTO_UDP,
                    sizeof(packet->udp) + sizeof(packet->payload), port);
}

static double elapsed_milliseconds(const struct timespec *start, const struct timespec *end)
{
    return (end->tv_sec - start->tv_sec) * 1000.0 +
           (end->tv_nsec - start->tv_nsec) / 1000000.0;
}

static void record_reply(probe_result_t *result, const icmp_parse_result_t *reply, double rtt)
{
    result->is_timeout = 0;
    result->rtt_ms = rtt;
    result->responder_addr = reply->responder_ip;
    result->result_type = reply->result_type;
    result->icmp_code = reply->icmp_code;
}

static int process_response(const traceroute_config_t *cfg, uint16_t port,
                             const uint8_t *buffer, size_t size,
                             const struct timespec *start, probe_result_t *result)
{
    struct timespec now;
    icmp_parse_result_t reply;
    if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) return -1;
    double rtt = elapsed_milliseconds(start, &now);
    if (rtt >= cfg->timeout_sec * 1000.0) return 2;
    if (!parse_and_validate_icmp(buffer, size, cfg->local_src_port, port,
                                cfg->target_addr.s_addr, &reply)) return 0;
    record_reply(result, &reply, rtt);
    return 1;
}

static int await_response(const traceroute_config_t *cfg, uint16_t port, int fd,
                           const struct timespec *start, probe_result_t *result)
{
    uint8_t buffer[512];
    struct timespec deadline = *start;
    deadline.tv_sec += cfg->timeout_sec;
    int length;
    while ((length = receive_icmp_packet(fd, buffer, sizeof(buffer), &deadline)) > 0) {
        int status = process_response(cfg, port, buffer, (size_t)length, start, result);
        if (status != 0) return status < 0 ? -1 : 0;
    }
    return length < 0 ? -1 : 0;
}

static int pause_before_probe(const traceroute_config_t *cfg, const trace_context_t *context)
{
    if (context->sent_probes == 0 || cfg->pause_ms == 0) return 0;
    struct timespec pause = {cfg->pause_ms / 1000, (cfg->pause_ms % 1000) * 1000000L};
    while (nanosleep(&pause, &pause) < 0) {
        if (errno != EINTR) return -1;
    }
    return 0;
}

static int transmit_probe(const traceroute_config_t *cfg, trace_context_t *context,
                           const probe_packet_t *packet, struct timespec *start)
{
    if (clock_gettime(CLOCK_MONOTONIC, start) < 0) return -1;
    if (send_raw_packet(context->send_fd, (const uint8_t *)packet,
                        sizeof(*packet), &cfg->target_addr) < 0) return -1;
    context->sent_probes++;
    return 0;
}

static int execute_probe(const traceroute_config_t *cfg, trace_context_t *context,
                          int ttl, probe_result_t *result)
{
    probe_packet_t packet;
    struct timespec start;
    uint16_t port = (uint16_t)context->next_port++;
    *result = (probe_result_t){.is_timeout = 1};
    if (pause_before_probe(cfg, context) < 0) return -1;
    build_probe_packet(&packet, cfg, ttl, port);
    if (transmit_probe(cfg, context, &packet, &start) < 0) return -1;
    return await_response(cfg, port, context->recv_fd, &start, result);
}

static int target_reached(const probe_result_t *result, uint32_t target)
{
    return !result->is_timeout && result->result_type == ICMP_RES_TARGET_REACHED &&
           result->responder_addr.s_addr == target;
}

static int trace_hop(const traceroute_config_t *cfg, trace_context_t *context, int ttl)
{
    hop_output_t output;
    int reached = 0;
    print_hop_begin(ttl, &output);
    for (int probe = 0; probe < cfg->probes_per_hop; probe++) {
        probe_result_t result;
        if (execute_probe(cfg, context, ttl, &result) < 0) { print_hop_end(); return -1; }
        print_probe_result(&result, &output);
        reached |= target_reached(&result, cfg->target_addr.s_addr);
    }
    print_hop_end();
    return reached;
}

static int run_hops(const traceroute_config_t *cfg, trace_context_t *context)
{
    for (int ttl = cfg->first_ttl; ttl <= cfg->max_hops; ttl++) {
        int status = trace_hop(cfg, context, ttl);
        if (status != 0) return status < 0 ? -1 : 0;
    }
    return 0;
}

int traceroute_run(const traceroute_config_t *cfg)
{
    trace_context_t context = {-1, -1, cfg->base_dst_port, 0};
    if (open_trace_sockets(&context) < 0) return 1;
    print_traceroute_header(cfg);
    int status = run_hops(cfg, &context);
    if (status < 0) perror("Error ejecutando probe");
    close_trace_sockets(&context);
    return status < 0 ? 1 : 0;
}
