#include <cstdint>

extern "C" std::uint64_t context_prepare(std::uint32_t, std::uint32_t) noexcept;
extern "C" std::uint64_t context_mix(std::uint32_t, std::uint32_t) noexcept;

// Internal protection scope, not a DLL export. An ordinary C name is required
// by this native adapter; C++ static functions retain MSVC name decoration.
extern "C" __declspec(noinline) std::uint64_t context_adjust(std::uint64_t value,
                                                        std::uint32_t y) noexcept {
    const std::uint64_t delta = static_cast<std::uint64_t>(y) * 97ULL + 23ULL;
    if (y & 2U) return (value ^ (delta << 9)) + delta;
    return (value + delta) ^ (value >> 11);
}

extern "C" __declspec(noinline) std::uint64_t context_score(std::uint32_t x,
                                                           std::uint32_t y) noexcept {
    const std::uint64_t prepared = context_prepare(x, y);
    const std::uint64_t mixed = context_mix(static_cast<std::uint32_t>(prepared),
                                            y ^ static_cast<std::uint32_t>(prepared >> 32));
    return context_adjust(mixed, y);
}

extern "C" __declspec(noinline) std::uint64_t context_public(std::uint32_t x,
                                                            std::uint32_t y) noexcept {
    return context_score(x, y);
}
