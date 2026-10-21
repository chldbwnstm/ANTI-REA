#include <cstdint>

extern "C" std::uint64_t native_transform(std::uint32_t, std::uint32_t) noexcept;

// An explicitly public forwarding boundary, separate from the protected module.
extern "C" __declspec(dllexport) std::uint64_t public_transform(std::uint32_t x,
                                                            std::uint32_t y) noexcept {
    return native_transform(x, y);
}
