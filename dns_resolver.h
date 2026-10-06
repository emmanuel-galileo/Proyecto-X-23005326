#ifndef DNS_RESOLVER_H
#define DNS_RESOLVER_H

#include <stddef.h>
#include <netinet/in.h>

int resolve_target_hostname(const char *target, char *ip_out, size_t size,
                            struct in_addr *addr_out);
int reverse_dns_lookup(const struct in_addr *addr, char *name_out, size_t size);
int determine_local_ip_for_target(const struct in_addr *target,
                                  struct in_addr *local_out);

#endif
