#include "raw_socket.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static int enable_ip_hdrincl(int fd)
{
    int one = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("[raw_socket] Error en setsockopt(IP_HDRINCL)");
        return -1;
    }
    return 0;
}

/* Orquestador que cumple con modularCoding (<= 15 lineas) */
int create_raw_sender_socket(void)
{
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd < 0) {
        perror("[raw_socket] Error creando socket RAW de emision (¿estas corriendo con sudo?)");
        return -1;
    }
    if (enable_ip_hdrincl(fd) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int set_socket_timeout(int fd, int timeout_sec)
{
    struct timeval tv;
    tv.tv_sec  = timeout_sec;
    tv.tv_usec = 0;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        perror("[raw_socket] Error configurando SO_RCVTIMEO");
        return -1;
    }
    return 0;
}

/* Orquestador que cumple con modularCoding (<= 15 lineas) */
int create_icmp_receiver_socket(int timeout_sec)
{
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (fd < 0) {
        perror("[raw_socket] Error creando socket RAW ICMP (¿estas corriendo con sudo?)");
        return -1;
    }
    if (set_socket_timeout(fd, timeout_sec) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static void init_dest_sockaddr(struct sockaddr_in *dest, const char *dst_ip)
{
    memset(dest, 0, sizeof(*dest));
    dest->sin_family = AF_INET;
    dest->sin_addr.s_addr = inet_addr(dst_ip);
}

/* Orquestador que cumple con modularCoding (<= 15 lineas) */
int send_raw_packet(int fd, const uint8_t *packet, size_t packet_len, const char *dst_ip)
{
    struct sockaddr_in dest;
    init_dest_sockaddr(&dest, dst_ip);
    ssize_t sent = sendto(fd, packet, packet_len, 0,
                           (const struct sockaddr *)&dest, sizeof(dest));
    return (sent < 0) ? -1 : (int)sent;
}

/* Orquestador que cumple con modularCoding (<= 15 lineas) */
int receive_icmp_packet(int fd, uint8_t *buffer, size_t max_len, struct sockaddr_in *src_addr)
{
    socklen_t addr_len = sizeof(*src_addr);
    ssize_t recvd = recvfrom(fd, buffer, max_len, 0,
                             (struct sockaddr *)src_addr, &addr_len);
    return (recvd < 0) ? -1 : (int)recvd;
}

void close_socket_fd(int fd)
{
    if (fd >= 0) {
        close(fd);
    }
}