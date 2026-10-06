#include "raw_socket.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>

static int enable_ip_header(int fd)
{
    int enabled = 1;
    return setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &enabled, sizeof(enabled));
}

static int make_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    return flags < 0 ? -1 : fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int configure_socket(int fd, int (*configure)(int), const char *label)
{
    if (fd >= 0 && configure(fd) == 0) return fd;
    perror(label);
    close_socket_fd(fd);
    return -1;
}

int create_raw_sender_socket(void)
{
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    return configure_socket(fd, enable_ip_header, "Error: socket RAW/IP_HDRINCL (requiere permisos RAW)");
}

int create_icmp_receiver_socket(void)
{
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    return configure_socket(fd, make_nonblocking, "Error: socket RAW ICMP (requiere permisos RAW)");
}

static int remaining_milliseconds(const struct timespec *deadline)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) return -1;
    int64_t nanoseconds = ((int64_t)deadline->tv_sec - now.tv_sec) * 1000000000LL +
                          deadline->tv_nsec - now.tv_nsec;
    if (nanoseconds <= 0) return 0;
    return (int)((nanoseconds + 999999) / 1000000);
}

static int readiness_status(short events)
{
    if (events & POLLNVAL) { errno = EBADF; return -1; }
    if (events & POLLERR) { errno = EIO; return -1; }
    if (events & POLLIN) return 1;
    errno = EIO;
    return -1;
}

static int wait_for_packet(int fd, const struct timespec *deadline)
{
    struct pollfd descriptor = {fd, POLLIN, 0};
    while (1) {
        int remaining = remaining_milliseconds(deadline);
        if (remaining <= 0) return remaining;
        int status = poll(&descriptor, 1, remaining);
        if (status > 0) return readiness_status(descriptor.revents);
        if (status < 0 && errno != EINTR) return -1;
    }
}

static int received_before_deadline(ssize_t length, const struct timespec *deadline)
{
    int remaining = remaining_milliseconds(deadline);
    return remaining <= 0 ? remaining : (int)length;
}

int receive_icmp_packet(int fd, uint8_t *buffer, size_t size,
                        const struct timespec *deadline)
{
    int ready;
    while ((ready = wait_for_packet(fd, deadline)) > 0) {
        ssize_t length = recv(fd, buffer, size, 0);
        if (length >= 0) return received_before_deadline(length, deadline);
        if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) return -1;
    }
    return ready;
}

int send_raw_packet(int fd, const uint8_t *packet, size_t size,
                     const struct in_addr *target)
{
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_addr = *target;
    ssize_t sent;
    do {
        sent = sendto(fd, packet, size, 0, (const struct sockaddr *)&address, sizeof(address));
    } while (sent < 0 && errno == EINTR);
    if (sent < 0) return -1;
    if ((size_t)sent != size) { errno = EIO; return -1; }
    return 0;
}

void close_socket_fd(int fd)
{
    if (fd >= 0) close(fd);
}
