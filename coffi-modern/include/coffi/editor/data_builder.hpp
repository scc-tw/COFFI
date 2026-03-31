#pragma once

/// Binary buffer builder for constructing PE data structures.
/// Supports write, reserve-then-patch, alignment, and string writes.

#include <cstdint>
#include <cstring>
#include <string_view>
#include <type_traits>
#include <vector>
#include <coffi/core/error.hpp>
#include <coffi/core/result.hpp>
#include <coffi/core/safe_math.hpp>

namespace coffi {

class data_builder {
    std::vector<char> buf_;

public:
    data_builder() = default;
    explicit data_builder(std::size_t reserve) { buf_.reserve(reserve); }

    [[nodiscard]] uint32_t pos() const noexcept {
        return static_cast<uint32_t>(buf_.size());
    }

    template <typename T>
    [[nodiscard]] result<uint32_t> write(const T& val) noexcept {
        static_assert(std::is_trivially_copyable_v<T>);
        auto off = pos();
        buf_.resize(buf_.size() + sizeof(T));
        std::memcpy(buf_.data() + off, &val, sizeof(T));
        return off;
    }

    [[nodiscard]] result<uint32_t> write_bytes(const void* data, uint32_t len) noexcept {
        auto off = pos();
        buf_.resize(buf_.size() + len);
        std::memcpy(buf_.data() + off, data, len);
        return off;
    }

    [[nodiscard]] result<uint32_t> write_str(std::string_view s) noexcept {
        auto off = pos();
        buf_.resize(buf_.size() + s.size() + 1);
        std::memcpy(buf_.data() + off, s.data(), s.size());
        buf_[off + s.size()] = '\0';
        return off;
    }

    template <typename T>
    [[nodiscard]] result<uint32_t> reserve() noexcept {
        static_assert(std::is_trivially_copyable_v<T>);
        auto off = pos();
        buf_.resize(buf_.size() + sizeof(T), 0);
        return off;
    }

    [[nodiscard]] result<uint32_t> reserve_bytes(uint32_t len) noexcept {
        auto off = pos();
        buf_.resize(buf_.size() + len, 0);
        return off;
    }

    template <typename T>
    [[nodiscard]] result<void> patch(uint32_t offset, const T& val) noexcept {
        static_assert(std::is_trivially_copyable_v<T>);
        auto end = checked_add<uint32_t>(offset, static_cast<uint32_t>(sizeof(T)));
        if (!end || *end > buf_.size()) return error_code::out_of_bounds;
        std::memcpy(buf_.data() + offset, &val, sizeof(T));
        return {};
    }

    [[nodiscard]] result<uint32_t> align(uint32_t boundary) noexcept {
        if (boundary == 0) return pos();
        uint32_t rem = pos() % boundary;
        if (rem == 0) return pos();
        uint32_t pad = boundary - rem;
        buf_.resize(buf_.size() + pad, 0);
        return pos();
    }

    [[nodiscard]] const char*  data() const noexcept { return buf_.data(); }
    [[nodiscard]] uint32_t     size() const noexcept { return static_cast<uint32_t>(buf_.size()); }
    [[nodiscard]] bool         empty() const noexcept { return buf_.empty(); }

    [[nodiscard]] std::vector<char> take() noexcept { return std::move(buf_); }
};

} // namespace coffi
