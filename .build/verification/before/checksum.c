#include "checksum.h"

static unsigned long accumulate_words(const uint16_t **buf, int *size)
{
    unsigned long sum = 0;
    while (*size > 1) {
        sum += **buf;
        (*buf)++;
        *size -= 2;
    }
    return sum;
}

static unsigned long add_odd_byte_if_any(unsigned long sum, const uint16_t *buf, int size)
{
    if (size == 1) {
        sum += *(const uint8_t *)buf;
    }
    return sum;
}

static uint16_t fold_32bit_sum(unsigned long sum)
{
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (uint16_t)(~sum);
}

/* Orquestador que cumple con modularCoding (<= 15 lineas) */
uint16_t calculate_checksum(const uint16_t *buffer, int size)
{
    unsigned long sum = accumulate_words(&buffer, &size);
    sum = add_odd_byte_if_any(sum, buffer, size);
    return fold_32bit_sum(sum);
}
