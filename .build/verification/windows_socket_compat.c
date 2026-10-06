#include "windows_socket_compat.h"
#include <errno.h>
#include <stdarg.h>
#include <io.h>
#undef socket
#undef socketpair
#undef close
#undef connect
#undef getsockname
#undef setsockopt
#undef send
#undef sendto
#undef recv
#undef fcntl
#undef poll

static SOCKET handles[32];
static int used[32];

static int socket_error(void)
{
    int error = WSAGetLastError();
    if (error == WSAEWOULDBLOCK) errno = EAGAIN;
    else if (error == WSAEINTR) errno = EINTR;
    else if (error == WSAEBADF || error == WSAENOTSOCK) errno = EBADF;
    else if (error == WSAEACCES) errno = EACCES;
    else errno = EIO;
    return -1;
}
static int initialize_winsock(void)
{
    static int initialized;
    WSADATA data;
    if (initialized) return 0;
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) return socket_error();
    initialized = 1;
    return 0;
}
static SOCKET native_socket(int fd)
{
    int index = fd - 1000;
    if (index < 0 || index >= 32 || !used[index]) { errno = EBADF; return INVALID_SOCKET; }
    return handles[index];
}
static int register_socket(SOCKET handle)
{
    if (handle == INVALID_SOCKET) return socket_error();
    for (int index = 0; index < 32; index++) {
        if (!used[index]) { used[index] = 1; handles[index] = handle; return index + 1000; }
    }
    closesocket(handle);
    errno = EMFILE;
    return -1;
}
int compat_socket(int family, int type, int protocol)
{
    if (initialize_winsock() < 0) return -1;
    return register_socket(socket(family, type, protocol));
}
int compat_close(int fd)
{
    if (fd < 1000) return _close(fd);
    SOCKET handle = native_socket(fd);
    if (handle == INVALID_SOCKET) return -1;
    used[fd - 1000] = 0;
    return closesocket(handle) == 0 ? 0 : socket_error();
}
int compat_connect(int fd, const struct sockaddr *address, socklen_t size)
{
    SOCKET handle = native_socket(fd);
    if (handle == INVALID_SOCKET) return -1;
    return connect(handle, address, size) == 0 ? 0 : socket_error();
}
int compat_getsockname(int fd, struct sockaddr *address, socklen_t *size)
{
    SOCKET handle = native_socket(fd);
    if (handle == INVALID_SOCKET) return -1;
    return getsockname(handle, address, size) == 0 ? 0 : socket_error();
}
int compat_setsockopt(int fd, int level, int option, const void *value, socklen_t size)
{
    SOCKET handle = native_socket(fd);
    if (handle == INVALID_SOCKET) return -1;
    return setsockopt(handle, level, option, value, size) == 0 ? 0 : socket_error();
}
ssize_t compat_send(int fd, const void *data, size_t size, int flags)
{
    SOCKET handle = native_socket(fd);
    if (handle == INVALID_SOCKET) return -1;
    int count = send(handle, data, (int)size, flags);
    return count < 0 ? socket_error() : count;
}
ssize_t compat_sendto(int fd, const void *data, size_t size, int flags,
                       const struct sockaddr *address, socklen_t length)
{
    SOCKET handle = native_socket(fd);
    if (handle == INVALID_SOCKET) return -1;
    int count = sendto(handle, data, (int)size, flags, address, length);
    return count < 0 ? socket_error() : count;
}
ssize_t compat_recv(int fd, void *data, size_t size, int flags)
{
    SOCKET handle = native_socket(fd);
    if (handle == INVALID_SOCKET) return -1;
    int count = recv(handle, data, (int)size, flags);
    return count < 0 ? socket_error() : count;
}
int compat_fcntl(int fd, int command, ...)
{
    SOCKET handle = native_socket(fd);
    if (handle == INVALID_SOCKET) return -1;
    if (command == F_GETFL) return 0;
    if (command != F_SETFL) { errno = EINVAL; return -1; }
    va_list arguments;
    va_start(arguments, command);
    u_long mode = (va_arg(arguments, int) & O_NONBLOCK) != 0;
    va_end(arguments);
    return ioctlsocket(handle, FIONBIO, &mode) == 0 ? 0 : socket_error();
}
int compat_poll(struct pollfd *descriptors, unsigned long count, int timeout)
{
    WSAPOLLFD native[32];
    if (count > 32) { errno = EINVAL; return -1; }
    for (unsigned long index = 0; index < count; index++) {
        native[index].fd = native_socket(descriptors[index].fd);
        if (native[index].fd == INVALID_SOCKET) { descriptors[index].revents = POLLNVAL; return 1; }
        native[index].events = descriptors[index].events;
        native[index].revents = 0;
    }
    int status = WSAPoll(native, count, timeout);
    if (status < 0) return socket_error();
    for (unsigned long index = 0; index < count; index++) descriptors[index].revents = native[index].revents;
    return status;
}
static int bind_loopback(int fd, struct sockaddr_in *address)
{
    *address = (struct sockaddr_in){0};
    address->sin_family = AF_INET;
    address->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(native_socket(fd), (const struct sockaddr *)address, sizeof(*address)) < 0)
        return socket_error();
    socklen_t size = sizeof(*address);
    return compat_getsockname(fd, (struct sockaddr *)address, &size);
}
int compat_socketpair(int family, int type, int protocol, int pair[2])
{
    (void)family; (void)protocol;
    struct sockaddr_in first, second;
    pair[0] = compat_socket(AF_INET, type, 0);
    pair[1] = compat_socket(AF_INET, type, 0);
    if (pair[0] < 0 || pair[1] < 0) return -1;
    if (bind_loopback(pair[0], &first) < 0 || bind_loopback(pair[1], &second) < 0) return -1;
    if (compat_connect(pair[0], (const struct sockaddr *)&second, sizeof(second)) < 0) return -1;
    return compat_connect(pair[1], (const struct sockaddr *)&first, sizeof(first));
}
