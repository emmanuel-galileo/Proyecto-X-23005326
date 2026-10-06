#ifndef WINDOWS_SOCKET_COMPAT_H
#define WINDOWS_SOCKET_COMPAT_H
#include <winsock2.h>
#include <ws2tcpip.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#include <stddef.h>
#ifndef F_GETFL
#define F_GETFL 3
#define F_SETFL 4
#define O_NONBLOCK 0x800
#endif
#define pollfd compat_pollfd
struct pollfd { int fd; short events; short revents; };
int compat_socket(int, int, int);
int compat_socketpair(int, int, int, int[2]);
int compat_close(int);
int compat_connect(int, const struct sockaddr *, socklen_t);
int compat_getsockname(int, struct sockaddr *, socklen_t *);
int compat_setsockopt(int, int, int, const void *, socklen_t);
ssize_t compat_send(int, const void *, size_t, int);
ssize_t compat_sendto(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
ssize_t compat_recv(int, void *, size_t, int);
int compat_fcntl(int, int, ...);
int compat_poll(struct pollfd *, unsigned long, int);
#define socket compat_socket
#define socketpair compat_socketpair
#define close compat_close
#define connect compat_connect
#define getsockname compat_getsockname
#define setsockopt compat_setsockopt
#define send compat_send
#define sendto compat_sendto
#define recv compat_recv
#define fcntl compat_fcntl
#define poll compat_poll
#endif
