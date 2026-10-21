#include "core.hpp"

namespace core {
static uint32_t tweak(uint32_t a, uint32_t b) {
    return (a ^ UINT32_C(53)) + (b * UINT32_C(97));
}

uint32_t mix(uint32_t a, uint32_t b) {
    uint32_t value = tweak(a, b);
    return (value << 7) ^ (value >> 9) ^ UINT32_C(0x96a5f317);
}
}
