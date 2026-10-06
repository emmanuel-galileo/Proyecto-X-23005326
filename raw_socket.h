#ifndef RAW_SOCKET_H
#define RAW_SOCKET_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include <netinet/in.h>

int create_raw_sender_socket(void);
int create_icmp_receiver_socket(void);
/* Returns 0 on complete transmission, -1 on error. */
int send_raw_packet(int fd, const uint8_t *packet, size_t size,
                     const struct in_addr *target);
/* Returns bytes received, 0 at the deadline, or -1 on error. */
int receive_icmp_packet(int fd, uint8_t *buffer, size_t size,
                        const struct timespec *deadline);
void close_socket_fd(int fd);

#endif
