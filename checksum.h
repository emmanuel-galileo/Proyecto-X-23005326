#ifndef CHECKSUM_H
#define CHECKSUM_H

#include <stdint.h>
#include <stddef.h>

/* Returns a host-order checksum. Store it in a packet with htons(). */
uint16_t calculate_checksum(const void *buffer, size_t size);
/* All segments except the last must have an even length. */
uint32_t checksum_accumulate(uint32_t sum, const void *buffer, size_t size);
uint16_t checksum_finish(uint32_t sum);

#endif
