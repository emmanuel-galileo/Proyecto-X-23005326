#ifndef TRACEROUTE_CLI_H
#define TRACEROUTE_CLI_H

#include "traceroute_engine.h"

void traceroute_config_defaults(traceroute_config_t *cfg);
/* 0: valid configuration; 1: help displayed; -1: invalid arguments. */
int traceroute_parse_cli(int argc, char **argv, traceroute_config_t *cfg);

#endif
