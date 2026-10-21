#include <cstdint>

extern "C" std::uint64_t native_transform(std::uint32_t x, std::uint32_t y) noexcept {
    std::uint64_t value = (std::uint64_t{x} << 17) ^ (std::uint64_t{y} + 0x9183u);
    for (std::uint32_t i = 0; i < 4; ++i) {
        value ^= value >> 13;
        value *= 0x100000001b3ULL;
        if ((value ^ i) & 1) value += (std::uint64_t{y} << 7) + i;
        else value ^= (std::uint64_t{x} << 11) + 0x51edu;
    }
    return value + (std::uint64_t{x} ^ y);
}
