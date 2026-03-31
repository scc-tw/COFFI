#pragma once

#include <cstdint>
#include <type_traits>

namespace coffi {

enum class byte_order { little, big };

// Compile-time native byte-order detection
namespace detail {
constexpr byte_order detect_native() noexcept {
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return byte_order::big;
#else
    return byte_order::little;  // x86 / x64 / most ARM
#endif
}
} // namespace detail

inline constexpr byte_order native_byte_order = detail::detect_native();

// ---------- Byte-swap overloads ----------

constexpr uint8_t  byte_swap(uint8_t  v) noexcept { return v; }

constexpr uint16_t byte_swap(uint16_t v) noexcept {
    return static_cast<uint16_t>((v >> 8) | (v << 8));
}

constexpr uint32_t byte_swap(uint32_t v) noexcept {
    return ((v >> 24) & 0x000000FFu) |
           ((v >>  8) & 0x0000FF00u) |
           ((v <<  8) & 0x00FF0000u) |
           ((v << 24) & 0xFF000000u);
}

constexpr uint64_t byte_swap(uint64_t v) noexcept {
    return ((v >> 56) & 0x00000000000000FFull) |
           ((v >> 40) & 0x000000000000FF00ull) |
           ((v >> 24) & 0x0000000000FF0000ull) |
           ((v >>  8) & 0x00000000FF000000ull) |
           ((v <<  8) & 0x000000FF00000000ull) |
           ((v << 24) & 0x0000FF0000000000ull) |
           ((v << 40) & 0x00FF000000000000ull) |
           ((v << 56) & 0xFF00000000000000ull);
}

// Signed overloads delegate to unsigned
constexpr int8_t  byte_swap(int8_t  v) noexcept { return v; }
constexpr int16_t byte_swap(int16_t v) noexcept { return static_cast<int16_t>(byte_swap(static_cast<uint16_t>(v))); }
constexpr int32_t byte_swap(int32_t v) noexcept { return static_cast<int32_t>(byte_swap(static_cast<uint32_t>(v))); }
constexpr int64_t byte_swap(int64_t v) noexcept { return static_cast<int64_t>(byte_swap(static_cast<uint64_t>(v))); }

// ---------- Conversion helpers ----------

template <typename T>
constexpr T to_native(T value, byte_order source) noexcept {
    return (source == native_byte_order) ? value : byte_swap(value);
}

template <typename T>
constexpr T from_native(T value, byte_order target) noexcept {
    return (target == native_byte_order) ? value : byte_swap(value);
}

// ---------- Endian-aware value wrapper ----------
// Use in custom structs where you want automatic conversion on access.
// PE format structs use raw integers since they are always LE and we read via memcpy.

template <typename T, byte_order Order>
struct endian_val {
    T raw;
    constexpr T   get() const noexcept { return to_native(raw, Order); }
    constexpr void set(T v) noexcept   { raw = from_native(v, Order); }
    constexpr operator T() const noexcept { return get(); }
    constexpr endian_val& operator=(T v) noexcept { set(v); return *this; }
};

// Convenience aliases (PE is always little-endian)
template <typename T> using le = endian_val<T, byte_order::little>;
template <typename T> using be = endian_val<T, byte_order::big>;

} // namespace coffi
