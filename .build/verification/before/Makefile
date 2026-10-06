CC = gcc
CFLAGS = -O2 -Wall -Wextra -Werror -pedantic -std=gnu99 -g
TARGET = my_traceroute
OBJS = traceroute_main.o traceroute_engine.o ip_header.o udp_header.o icmp_parser.o dns_resolver.o checksum.o raw_socket.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o $(TARGET)

.PHONY: all clean