#include <cstdint>

// Synthetic non-security score. No authentication, cryptography or secret data.
extern "C" __declspec(noinline) std::uint64_t context_mix(std::uint32_t x,
                                                         std::uint32_t y) noexcept {
    std::uint64_t value = static_cast<std::uint64_t>(x) * 1000003ULL + y;
    for (unsigned round = 0; round < 3; ++round) {
        value ^= value >> 13;
        value += (static_cast<std::uint64_t>(y) + round + 17ULL) * 65537ULL;
        value *= 257ULL;
    }
    return value ^ (value >> 29);
}
