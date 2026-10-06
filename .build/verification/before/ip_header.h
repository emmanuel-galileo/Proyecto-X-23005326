#ifndef IP_HEADER_H
#define IP_HEADER_H

#include <stdint.h>

/*
 * Estructura del header IPv4 (RFC 791), 20 bytes sin opciones.
 */
#pragma pack(push, 1)
typedef struct {
    uint8_t  ihl_version;   /* 4 bits version + 4 bits IHL */
    uint8_t  tos;            /* Type of Service */
    uint16_t total_length;   /* Longitud total (header + payload) */
    uint16_t id;              /* Identificador */
    uint16_t flags_fo;       /* 3 bits flags + 13 bits fragment offset */
    uint8_t  ttl;              /* Time To Live */
    uint8_t  protocol;        /* Protocolo encapsulado (ej. 17 = UDP) */
    uint16_t checksum;        /* Checksum del header IP */
    uint32_t src_addr;        /* IP origen en orden de red */
    uint32_t dst_addr;        /* IP destino en orden de red */
} ip_header_t;
#pragma pack(pop)

#define IP_HEADER_LEN sizeof(ip_header_t)

/*
 * Llena iph con valores IPv4 estándar, permitiendo configurar TTL y protocolo dinámico.
 */
void build_ip_header(ip_header_t *iph, const char *src_ip, const char *dst_ip,
                      uint8_t ttl, uint8_t protocol, uint16_t payload_len);

#endif /* IP_HEADER_H */
