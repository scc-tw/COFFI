#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>
#include <type_traits>
#include <coffi/core/error.hpp>
#include <coffi/core/result.hpp>

namespace coffi {

// ---------- Overflow-safe unsigned arithmetic ----------

template <typename T>
[[nodiscard]] constexpr std::enable_if_t<std::is_unsigned_v<T>, result<T>>
checked_add(T a, T b) noexcept {
    if (a > std::numeric_limits<T>::max() - b) return error_code::overflow;
    return static_cast<T>(a + b);
}

template <typename T>
[[nodiscard]] constexpr std::enable_if_t<std::is_unsigned_v<T>, result<T>>
checked_mul(T a, T b) noexcept {
    if (a != 0 && b > std::numeric_limits<T>::max() / a) return error_code::overflow;
    return static_cast<T>(a * b);
}

// ---------- Alignment utilities ----------
// Guards against alignment==0 (division by zero from 1ee0be8 audit).

template <typename T>
[[nodiscard]] constexpr std::enable_if_t<std::is_unsigned_v<T>, T>
align_to(T value, T alignment) noexcept {
    if (alignment == 0) return value;
    T remainder = value % alignment;
    if (remainder == 0) return value;
    return value + (alignment - remainder);
}

template <typename T>
[[nodiscard]] constexpr std::enable_if_t<std::is_unsigned_v<T>, result<T>>
checked_align_to(T value, T alignment) noexcept {
    if (alignment == 0) return value;
    T remainder = value % alignment;
    if (remainder == 0) return value;
    return checked_add(value, static_cast<T>(alignment - remainder));
}

// ---------- Narrowing cast with overflow check ----------

template <typename To, typename From>
[[nodiscard]] constexpr std::enable_if_t<
    std::is_arithmetic_v<From> && std::is_arithmetic_v<To>, result<To>>
narrow_cast(From value) noexcept {
    auto narrowed = static_cast<To>(value);
    if (static_cast<From>(narrowed) != value) return error_code::overflow;
    return narrowed;
}

} // namespace coffi
