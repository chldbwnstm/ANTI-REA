#include <stdint.h>

/* Synthetic arithmetic, not cryptography, authentication, or access control. */
uint64_t native_transform(uint32_t x, uint32_t y) {
    uint64_t value = ((uint64_t)x << 17) ^ ((uint64_t)y + 0x9183u);
    for (uint32_t i = 0; i < 4; ++i) {
        value ^= value >> 13;
        value *= 0x100000001b3ULL;
        if ((value ^ i) & 1) value += ((uint64_t)y << 7) + i;
        else value ^= ((uint64_t)x << 11) + 0x51edu;
    }
    return value + ((uint64_t)x ^ y);
}
