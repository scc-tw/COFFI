#pragma once

#include <variant>
#include <optional>
#include <type_traits>
#include <functional>
#include <utility>
#include <coffi/core/error.hpp>

namespace coffi {

// ---------- Tag type to disambiguate error construction ----------

template <typename E>
struct unexpected {
    E value;
    explicit constexpr unexpected(E e) noexcept(std::is_nothrow_move_constructible_v<E>)
        : value(std::move(e)) {}
};

template <typename E>
unexpected(E) -> unexpected<E>;

// ---------- Primary template: result<T, E> ----------

template <typename T, typename E = error_code>
class result {
    std::variant<T, unexpected<E>> data_;

public:
    using value_type = T;
    using error_type = E;

    // --- Value constructors ---
    constexpr result(T val) noexcept(std::is_nothrow_move_constructible_v<T>)
        : data_(std::move(val)) {}

    // --- Error constructors ---
    constexpr result(unexpected<E> err) noexcept(std::is_nothrow_move_constructible_v<E>)
        : data_(std::move(err)) {}

    // Convenience: construct from bare E (SFINAE-guarded against T == E)
    template <typename U = E,
              std::enable_if_t<!std::is_same_v<std::decay_t<T>, std::decay_t<U>>, int> = 0>
    constexpr result(E err) noexcept
        : data_(unexpected<E>{std::move(err)}) {}

    // --- Observers ---
    [[nodiscard]] constexpr bool has_value() const noexcept {
        return std::holds_alternative<T>(data_);
    }
    [[nodiscard]] constexpr explicit operator bool() const noexcept { return has_value(); }

    // --- Value access ---
    [[nodiscard]] constexpr T&       value() &       { return std::get<T>(data_); }
    [[nodiscard]] constexpr const T& value() const & { return std::get<T>(data_); }
    [[nodiscard]] constexpr T&&      value() &&      { return std::get<T>(std::move(data_)); }

    [[nodiscard]] constexpr T value_or(T fallback) const & {
        return has_value() ? value() : std::move(fallback);
    }

    // --- Error access ---
    [[nodiscard]] constexpr const E& error() const & {
        return std::get<unexpected<E>>(data_).value;
    }

    // --- Pointer-like syntax ---
    [[nodiscard]] constexpr const T& operator*()  const &  { return value(); }
    [[nodiscard]] constexpr T&       operator*()  &        { return value(); }
    [[nodiscard]] constexpr const T* operator->() const    { return &value(); }
    [[nodiscard]] constexpr T*       operator->()          { return &value(); }

    // --- Monadic: map (transform value, propagate error) ---
    template <typename F>
    [[nodiscard]] constexpr auto map(F&& f) const &
        -> result<std::invoke_result_t<F, const T&>, E>
    {
        if (has_value()) return std::invoke(std::forward<F>(f), value());
        return error();
    }

    // --- Monadic: and_then (chain operations returning result) ---
    template <typename F>
    [[nodiscard]] constexpr auto and_then(F&& f) const &
        -> std::invoke_result_t<F, const T&>
    {
        if (has_value()) return std::invoke(std::forward<F>(f), value());
        return error();
    }
};

// ---------- Void specialisation ----------

template <typename E>
class result<void, E> {
    std::optional<E> error_;

public:
    using value_type = void;
    using error_type = E;

    constexpr result() noexcept : error_(std::nullopt) {}
    constexpr result(unexpected<E> err) noexcept : error_(std::move(err.value)) {}
    constexpr result(E err) noexcept : error_(std::move(err)) {}

    [[nodiscard]] constexpr bool has_value() const noexcept { return !error_.has_value(); }
    [[nodiscard]] constexpr explicit operator bool() const noexcept { return has_value(); }
    [[nodiscard]] constexpr const E& error() const & { return *error_; }
};

} // namespace coffi
