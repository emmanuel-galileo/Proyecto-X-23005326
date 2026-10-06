#include "dns_resolver.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

static void setup_hints(struct addrinfo *hints)
{
    memset(hints, 0, sizeof(*hints));
    hints->ai_family   = AF_INET;
    hints->ai_socktype = SOCK_DGRAM;
}

static int extract_ipv4_addr(const struct addrinfo *res, char *ip_str_out,
                             size_t ip_str_sz, struct in_addr *addr_out)
{
    const struct sockaddr_in *sa = (const struct sockaddr_in *)res->ai_addr;
    if (addr_out) *addr_out = sa->sin_addr;
    if (ip_str_out && ip_str_sz > 0) {
        if (!inet_ntop(AF_INET, &sa->sin_addr, ip_str_out, (socklen_t)ip_str_sz)) {
            return -1;
        }
    }
    return 0;
}

/* Orquestador que cumple con modularCoding (<= 15 lineas) */
int resolve_target_hostname(const char *target, char *ip_str_out, size_t ip_str_sz,
                            struct in_addr *addr_out)
{
    struct addrinfo hints, *res = NULL;
    setup_hints(&hints);
    if (getaddrinfo(target, NULL, &hints, &res) != 0 || !res) {
        return -1;
    }
    int rc = extract_ipv4_addr(res, ip_str_out, ip_str_sz, addr_out);
    freeaddrinfo(res);
    return rc;
}

static void setup_sockaddr_in(const struct in_addr *addr, struct sockaddr_in *sa)
{
    memset(sa, 0, sizeof(*sa));
    sa->sin_family = AF_INET;
    sa->sin_addr   = *addr;
}

/* Orquestador que cumple con modularCoding (<= 15 lineas) */
int reverse_dns_lookup(const struct in_addr *addr, char *hostname_out, size_t max_len)
{
    struct sockaddr_in sa;
    setup_sockaddr_in(addr, &sa);
    int rc = getnameinfo((struct sockaddr *)&sa, sizeof(sa),
                         hostname_out, (socklen_t)max_len, NULL, 0, NI_NAMEREQD);
    if (rc != 0) {
        hostname_out[0] = '\0';
        return 0;
    }
    return 1;
}

static int query_local_socket_ip(int fd, char *local_ip_out, size_t max_len)
{
    struct sockaddr_in local_sa;
    socklen_t len = sizeof(local_sa);
    if (getsockname(fd, (struct sockaddr *)&local_sa, &len) < 0) return -1;
    return inet_ntop(AF_INET, &local_sa.sin_addr, local_ip_out, (socklen_t)max_len) ? 0 : -1;
}

/* Orquestador que cumple con modularCoding (<= 15 lineas) */
int determine_local_ip_for_target(const struct in_addr *target_addr,
                                  char *local_ip_out, size_t max_len)
{
    int dummy_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (dummy_fd < 0) return -1;

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr   = *target_addr;
    dest.sin_port   = htons(53);

    int rc = (connect(dummy_fd, (struct sockaddr *)&dest, sizeof(dest)) < 0) ? -1
             : query_local_socket_ip(dummy_fd, local_ip_out, max_len);
    close(dummy_fd);
    return rc;
}
