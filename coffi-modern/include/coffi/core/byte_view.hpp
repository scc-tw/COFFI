#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string_view>
#include <type_traits>
#include <coffi/core/error.hpp>
#include <coffi/core/result.hpp>
#include <coffi/core/safe_math.hpp>

namespace coffi {

/// Non-owning, immutable view over a contiguous byte sequence.
/// This is the foundation of all zero-copy parsing in coffi-modern.
/// All field reads use std::memcpy to avoid strict-aliasing UB and
/// alignment faults (addresses 1ee0be8 audit findings).
class byte_view {
public:
    using size_type = std::size_t;

    constexpr byte_view() noexcept = default;

    constexpr byte_view(const void* data, size_type size) noexcept
        : data_(static_cast<const std::byte*>(data)), size_(size) {}

    byte_view(std::string_view sv) noexcept
        : data_(reinterpret_cast<const std::byte*>(sv.data())), size_(sv.size()) {}

    // --- Basic accessors ---
    [[nodiscard]] constexpr const std::byte* data()  const noexcept { return data_; }
    [[nodiscard]] constexpr size_type        size()  const noexcept { return size_; }
    [[nodiscard]] constexpr bool             empty() const noexcept { return size_ == 0; }

    [[nodiscard]] constexpr std::byte operator[](size_type i) const noexcept {
        return data_[i];
    }

    // --- Safe sub-view (returns result to propagate errors) ---
    [[nodiscard]] result<byte_view> subview(size_type offset, size_type length) const noexcept {
        auto end = checked_add(offset, length);
        if (!end || *end > size_) return error_code::out_of_bounds;
        return byte_view{data_ + offset, length};
    }

    // Unchecked sub-view (use only after prior validation)
    [[nodiscard]] constexpr byte_view slice(size_type offset, size_type length) const noexcept {
        return {data_ + offset, length};
    }

    // --- Read a trivially-copyable value by copy (memcpy, alignment-safe) ---
    template <typename T>
    [[nodiscard]] result<T> read(size_type offset) const noexcept {
        static_assert(std::is_trivially_copyable_v<T>, "T must be trivially copyable");
        auto end = checked_add(offset, sizeof(T));
        if (!end || *end > size_) return error_code::out_of_bounds;
        T val;
        std::memcpy(&val, data_ + offset, sizeof(T));
        return val;
    }

    // --- Validate that an array of count T's fits at offset ---
    template <typename T>
    [[nodiscard]] result<byte_view> read_array(size_type offset, size_type count) const noexcept {
        static_assert(std::is_trivially_copyable_v<T>, "T must be trivially copyable");
        auto total = checked_mul(count, sizeof(T));
        if (!total) return error_code::overflow;
        auto end = checked_add(offset, *total);
        if (!end || *end > size_) return error_code::out_of_bounds;
        return byte_view{data_ + offset, *total};
    }

    // --- Read null-terminated C string ---
    [[nodiscard]] std::string_view read_cstring(size_type offset,
                                                size_type max_len = 0) const noexcept {
        if (offset >= size_) return {};
        auto avail = size_ - offset;
        if (max_len == 0 || max_len > avail) max_len = avail;
        auto ptr = reinterpret_cast<const char*>(data_ + offset);
        // strnlen: find NUL within max_len bytes
        size_type len = 0;
        while (len < max_len && ptr[len] != '\0') ++len;
        return {ptr, len};
    }

    // --- Read a fixed-width name field (e.g. section name, 8 bytes) ---
    [[nodiscard]] std::string_view read_fixed_string(size_type offset,
                                                     size_type field_len) const noexcept {
        auto end = checked_add(offset, field_len);
        if (!end || *end > size_) return {};
        auto ptr = reinterpret_cast<const char*>(data_ + offset);
        size_type len = 0;
        while (len < field_len && ptr[len] != '\0') ++len;
        return {ptr, len};
    }

    // --- Raw char pointer (for interop) ---
    [[nodiscard]] const char* as_chars(size_type offset = 0) const noexcept {
        if (offset >= size_) return nullptr;
        return reinterpret_cast<const char*>(data_ + offset);
    }

private:
    const std::byte* data_ = nullptr;
    size_type        size_ = 0;
};

} // namespace coffi
