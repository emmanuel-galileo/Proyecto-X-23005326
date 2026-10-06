#include "dns_resolver.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

static int extract_address(const struct addrinfo *result, char *ip_out,
                            size_t size, struct in_addr *addr_out)
{
    const struct sockaddr_in *address = (const struct sockaddr_in *)result->ai_addr;
    *addr_out = address->sin_addr;
    return inet_ntop(AF_INET, addr_out, ip_out, (socklen_t)size) ? 0 : -1;
}

int resolve_target_hostname(const char *target, char *ip_out, size_t size,
                            struct in_addr *addr_out)
{
    struct addrinfo hints = {0}, *result = NULL;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    if (getaddrinfo(target, NULL, &hints, &result) != 0) return -1;
    int status = extract_address(result, ip_out, size, addr_out);
    freeaddrinfo(result);
    return status;
}

int reverse_dns_lookup(const struct in_addr *addr, char *name_out, size_t size)
{
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_addr = *addr;
    name_out[0] = '\0';
    int status = getnameinfo((const struct sockaddr *)&address, sizeof(address),
                             name_out, (socklen_t)size, NULL, 0, NI_NAMEREQD);
    if (status != 0) name_out[0] = '\0';
    return status == 0;
}

static int query_local_address(int fd, struct in_addr *local_out)
{
    struct sockaddr_in address;
    socklen_t size = sizeof(address);
    if (getsockname(fd, (struct sockaddr *)&address, &size) < 0) return -1;
    if (address.sin_addr.s_addr == INADDR_ANY) { errno = EADDRNOTAVAIL; return -1; }
    *local_out = address.sin_addr;
    return 0;
}

static int connect_to_target(int fd, const struct in_addr *target)
{
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_addr = *target;
    address.sin_port = htons(53);
    return connect(fd, (const struct sockaddr *)&address, sizeof(address));
}

int determine_local_ip_for_target(const struct in_addr *target,
                                  struct in_addr *local_out)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    int status = connect_to_target(fd, target);
    if (status == 0) status = query_local_address(fd, local_out);
    int saved_errno = errno;
    close(fd);
    errno = saved_errno;
    return status;
}
