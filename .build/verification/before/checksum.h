#ifndef CHECKSUM_H
#define CHECKSUM_H

#include <stdint.h>
#include <stddef.h>

/*
 * Checksum genérico "Internet checksum" (RFC 1071).
 * Suma en complemento a uno a 16 bits con plegado de acarreo.
 */
uint16_t calculate_checksum(const uint16_t *buffer, int size);

#endif /* CHECKSUM_H */
