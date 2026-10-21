/* Public, non-security FFI fixture. Not the private protected ledger algorithm. */
#include <stdint.h>
#ifdef _WIN32
#define API __declspec(dllexport)
#else
#define API __attribute__((visibility("default")))
#endif
API uint64_t mix(uint32_t x, uint32_t y) { return ((uint64_t)x << 32) | y; }
API uint32_t echoU32(uint32_t x) { return x; }
API int32_t echoI32(int32_t x) { return x; }
API uint64_t echoU64(uint64_t x) { return x; }
API int64_t echoI64(int64_t x) { return x; }
/* A legal C export can be a reserved identifier in a consumer language. */
API uint64_t class(uint64_t x) { return x; }
API void touch(void) {}
