#ifndef UDP_HEADER_H
#define UDP_HEADER_H

#include <stdint.h>
#include <stddef.h>

/*
 * Estructura de cabecera UDP (RFC 768), 8 bytes fijos.
 */
#pragma pack(push, 1)
typedef struct {
    uint16_t src_port;  /* Puerto origen */
    uint16_t dst_port;  /* Puerto destino */
    uint16_t length;    /* Longitud cabecera + payload en bytes */
    uint16_t checksum;  /* Checksum de transporte */
} udp_header_t;
#pragma pack(pop)

#define UDP_HEADER_LEN sizeof(udp_header_t)

/*
 * Inicializa la cabecera UDP con los puertos y longitud especificados.
 */
void build_udp_header(udp_header_t *udph, uint16_t src_port, uint16_t dst_port,
                       uint16_t payload_len);

/*
 * Calcula el checksum UDP incluyendo el Pseudo-Header IPv4 (RFC 768).
 */
uint16_t calculate_udp_checksum(uint32_t src_addr, uint32_t dst_addr,
                                 const udp_header_t *udph,
                                 const uint8_t *payload, uint16_t payload_len);

#endif /* UDP_HEADER_H */
