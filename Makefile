CC = gcc
CPPFLAGS = -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE
CFLAGS = -O2 -Wall -Wextra -Werror -pedantic -std=c99 -g
TARGET = my_traceroute
SOURCES = traceroute_main.c traceroute_cli.c traceroute_engine.c traceroute_output.c \
          ip_header.c udp_header.c icmp_parser.c dns_resolver.c checksum.c raw_socket.c
OBJS = $(SOURCES:%.c=.build/%.o)
CORE_OBJS = .build/traceroute_cli.o .build/ip_header.o .build/udp_header.o \
            .build/icmp_parser.o .build/checksum.o
ENGINE_OBJS = .build/traceroute_engine.o .build/traceroute_output.o \
              .build/ip_header.o .build/udp_header.o .build/icmp_parser.o .build/checksum.o
TESTS = .build/test_core .build/test_engine .build/test_raw_socket

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

.build/%.o: %.c
	@mkdir -p .build
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c $< -o $@

.build/test_core: tests/test_core.c $(CORE_OBJS)
	$(CC) $(CPPFLAGS) $(CFLAGS) -I. $(LDFLAGS) -o $@ $^ $(LDLIBS)

.build/test_engine: tests/test_engine.c $(ENGINE_OBJS)
	$(CC) $(CPPFLAGS) $(CFLAGS) -I. $(LDFLAGS) -o $@ $^ $(LDLIBS)

.build/test_raw_socket: tests/test_raw_socket.c .build/raw_socket.o
	$(CC) $(CPPFLAGS) $(CFLAGS) -I. $(LDFLAGS) -o $@ $^ $(LDLIBS)

test: $(TESTS)
	@set -e; for test in $(TESTS); do ./$$test; done

network-test:
	sh tests/compare_network.sh

clean:
	rm -f $(OBJS) $(OBJS:.o=.d) $(TESTS) $(TARGET) *.o

-include $(OBJS:.o=.d)
.PHONY: all clean test network-test
