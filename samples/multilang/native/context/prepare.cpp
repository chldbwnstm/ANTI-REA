#include <cstdint>

extern "C" __declspec(noinline) std::uint64_t context_prepare(std::uint32_t x,
                                                             std::uint32_t y) noexcept {
    std::uint64_t value = static_cast<std::uint64_t>(x) * 37ULL + y + 101ULL;
    if (x & 1U) value ^= static_cast<std::uint64_t>(y) << 21;
    else value += static_cast<std::uint64_t>(x) << 17;
    return value;
}
