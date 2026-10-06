#ifndef RAW_SOCKET_H
#define RAW_SOCKET_H

#include <stdint.h>
#include <stddef.h>
#include <netinet/in.h>

/*
 * Crea el socket crudo de emisión con IP_HDRINCL habilitado.
 * Retorna descriptor o -1 en caso de error.
 */
int create_raw_sender_socket(void);

/*
 * Crea el socket crudo de recepción para ICMP con timeout configurado en segundos.
 * Retorna descriptor o -1 en caso de error.
 */
int create_icmp_receiver_socket(int timeout_sec);

/*
 * Envía un datagrama completo (IP + UDP + payload) hacia la dirección IP destino.
 */
int send_raw_packet(int fd, const uint8_t *packet, size_t packet_len, const char *dst_ip);

/*
 * Recibe un paquete ICMP entrante en buffer. Retorna bytes leídos o -1 en caso de timeout/error.
 */
int receive_icmp_packet(int fd, uint8_t *buffer, size_t max_len, struct sockaddr_in *src_addr);

/*
 * Cierra un descriptor de socket abierto.
 */
void close_socket_fd(int fd);

#endif /* RAW_SOCKET_H */