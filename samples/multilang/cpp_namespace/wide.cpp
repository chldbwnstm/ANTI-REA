#include "core.hpp"

namespace core {
uint64_t mix(uint64_t a, uint64_t b) {
    uint64_t x = a * UINT64_C(65537) + b + UINT64_C(713);
    for (uint32_t i = 0; i < 3; ++i) {
        x ^= x >> 13;
        x = x * UINT64_C(257) + (b ^ (UINT64_C(17) + i));
    }
    return x;
}

uint64_t finish(uint64_t value, uint64_t salt) {
    return (salt & 1) ? ((value ^ (salt << 9)) + salt) : ((value + salt) ^ (value >> 11));
}
}
