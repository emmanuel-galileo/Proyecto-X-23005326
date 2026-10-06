#include "raw_socket.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

static void open_pair(int descriptors[2])
{
    assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, descriptors) == 0);
    int flags = fcntl(descriptors[0], F_GETFL, 0);
    assert(flags >= 0 && fcntl(descriptors[0], F_SETFL, flags | O_NONBLOCK) == 0);
}

static struct timespec deadline_after(int milliseconds)
{
    struct timespec deadline;
    assert(clock_gettime(CLOCK_MONOTONIC, &deadline) == 0);
    deadline.tv_nsec += milliseconds * 1000000L;
    if (deadline.tv_nsec >= 1000000000L) { deadline.tv_sec++; deadline.tv_nsec -= 1000000000L; }
    return deadline;
}

static void test_ready_packet(void)
{
    int descriptors[2];
    uint8_t buffer[16];
    open_pair(descriptors);
    struct timespec deadline = deadline_after(500);
    assert(send(descriptors[1], "probe", 5, 0) == 5);
    assert(receive_icmp_packet(descriptors[0], buffer, sizeof(buffer), &deadline) == 5);
    assert(memcmp(buffer, "probe", 5) == 0);
    close(descriptors[0]);
    close(descriptors[1]);
}

static void test_empty_timeout(void)
{
    int descriptors[2];
    uint8_t buffer[16];
    open_pair(descriptors);
    struct timespec deadline = deadline_after(60);
    assert(receive_icmp_packet(descriptors[0], buffer, sizeof(buffer), &deadline) == 0);
    struct timespec now;
    assert(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
    assert(now.tv_sec > deadline.tv_sec ||
           (now.tv_sec == deadline.tv_sec && now.tv_nsec >= deadline.tv_nsec));
    close(descriptors[0]);
    close(descriptors[1]);
}

static void test_expired_and_invalid(void)
{
    int descriptors[2];
    uint8_t buffer[16];
    open_pair(descriptors);
    struct timespec deadline = deadline_after(500);
    deadline.tv_sec--;
    assert(send(descriptors[1], "late", 4, 0) == 4);
    assert(receive_icmp_packet(descriptors[0], buffer, sizeof(buffer), &deadline) == 0);
    close(descriptors[0]);
    deadline = deadline_after(500);
    assert(receive_icmp_packet(descriptors[0], buffer, sizeof(buffer), &deadline) == -1);
    assert(errno == EBADF);
    close(descriptors[1]);
}

int main(void)
{
    test_ready_packet();
    test_empty_timeout();
    test_expired_and_invalid();
    puts("socket deadlines: passed");
    return 0;
}
