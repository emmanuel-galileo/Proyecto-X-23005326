#ifndef TRACEROUTE_OUTPUT_H
#define TRACEROUTE_OUTPUT_H

#include "traceroute_engine.h"

typedef struct {
    struct in_addr last_addr;
    int has_addr;
} hop_output_t;

void print_traceroute_header(const traceroute_config_t *cfg);
void print_hop_begin(int ttl, hop_output_t *output);
void print_probe_result(const probe_result_t *result, hop_output_t *output);
void print_hop_end(void);

#endif
