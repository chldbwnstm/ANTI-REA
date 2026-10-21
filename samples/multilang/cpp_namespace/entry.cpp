#include "core.hpp"

extern "C" uint64_t public_score(uint64_t a, uint64_t b) {
    uint64_t wide = core::mix(a, b);
    uint64_t small = core::mix(static_cast<uint32_t>(a), static_cast<uint32_t>(b));
    return core::finish(wide ^ small, b);
}

#ifdef ANTIREA_PUBLIC_FORWARDER
extern "C" uint64_t public_forward(uint64_t a, uint64_t b) {
    return core::finish(a, b);
}
#endif
