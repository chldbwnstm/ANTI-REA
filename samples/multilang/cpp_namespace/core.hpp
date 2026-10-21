#pragma once
#include <stdint.h>

namespace core {
uint64_t mix(uint64_t a, uint64_t b);
uint32_t mix(uint32_t a, uint32_t b);
uint64_t finish(uint64_t value, uint64_t salt);
}
