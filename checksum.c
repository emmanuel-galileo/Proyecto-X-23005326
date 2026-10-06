#include "checksum.h"

uint32_t checksum_accumulate(uint32_t sum, const void *buffer, size_t size)
{
    const uint8_t *bytes = buffer;
    while (size >= 2) {
        sum += ((uint32_t)bytes[0] << 8) | bytes[1];
        bytes += 2;
        size -= 2;
    }
    if (size != 0) sum += (uint32_t)bytes[0] << 8;
    return sum;
}

uint16_t checksum_finish(uint32_t sum)
{
    while (sum >> 16) sum = (sum & 0xFFFFU) + (sum >> 16);
    return (uint16_t)~sum;
}

uint16_t calculate_checksum(const void *buffer, size_t size)
{
    return checksum_finish(checksum_accumulate(0, buffer, size));
}
