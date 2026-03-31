#pragma once

/// Zero-copy string table view.
/// Resolves COFF symbol names: inline (<=8 chars) or string-table offset.

#include <cstdint>
#include <cstring>
#include <string_view>
#include <coffi/core/byte_view.hpp>
#include <coffi/platform/schema.hpp>

namespace coffi {

class string_table_view {
    byte_view data_;  // Points to the string table (starts with 4-byte size field)

public:
    constexpr string_table_view() noexcept = default;
    explicit constexpr string_table_view(byte_view data) noexcept : data_(data) {}

    [[nodiscard]] constexpr std::size_t size()  const noexcept { return data_.size(); }
    [[nodiscard]] constexpr bool        empty() const noexcept { return data_.empty(); }

    /// Look up a string at the given byte offset within the table.
    [[nodiscard]] std::string_view get(uint32_t offset) const noexcept {
        if (offset >= data_.size()) return {};
        return data_.read_cstring(offset);
    }

    /// Resolve a COFF name field (8-byte array from symbol_record or section_header).
    ///
    /// Encoding:
    ///   - If first 4 bytes are zero → long name; bytes 4-7 = offset into string table.
    ///   - If name[0] == '/' → section long name; decimal offset follows the slash.
    ///   - Otherwise → inline name, up to 8 chars, NUL-padded.
    [[nodiscard]] std::string_view resolve_name(const char* name_field) const noexcept {
        // Check for string-table reference (symbol-style: first 4 bytes == 0)
        uint32_t first4;
        std::memcpy(&first4, name_field, sizeof(first4));

        if (first4 == 0 && !data_.empty()) {
            uint32_t offset;
            std::memcpy(&offset, name_field + 4, sizeof(offset));
            return get(offset);
        }

        // Check for section-style long name: "/123"
        if (name_field[0] == '/' && !data_.empty()) {
            // Parse decimal offset after '/'
            uint32_t offset = 0;
            for (int i = 1; i < 8 && name_field[i] >= '0' && name_field[i] <= '9'; ++i) {
                offset = offset * 10 + static_cast<uint32_t>(name_field[i] - '0');
            }
            return get(offset);
        }

        // Inline short name (up to COFFI_NAME_SIZE chars)
        std::size_t len = 0;
        while (len < COFFI_NAME_SIZE && name_field[len] != '\0') ++len;
        return {name_field, len};
    }
};

} // namespace coffi
