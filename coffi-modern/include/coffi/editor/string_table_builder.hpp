#pragma once

/// Mutable string table builder.
/// Auto-manages COFF string table: encodes short names inline,
/// long names as offset references into the table.

#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>
#include <coffi/platform/schema.hpp>

namespace coffi {

class string_table_builder {
    std::vector<char> table_;  // first 4 bytes = LE uint32 total size

public:
    string_table_builder() { clear(); }

    /// Add a string to the table. Returns its offset.
    /// Deduplicates: if already present, returns existing offset.
    [[nodiscard]] uint32_t add(std::string_view name) noexcept {
        // Search for existing entry (skip 4-byte size header)
        for (uint32_t i = 4; i < table_.size(); ) {
            auto existing = std::string_view(table_.data() + i);
            if (existing == name) return i;
            i += static_cast<uint32_t>(existing.size()) + 1;
        }
        // Append new entry
        auto off = static_cast<uint32_t>(table_.size());
        table_.insert(table_.end(), name.begin(), name.end());
        table_.push_back('\0');
        // Update size header
        uint32_t sz = static_cast<uint32_t>(table_.size());
        std::memcpy(table_.data(), &sz, 4);
        return off;
    }

    /// Encode a name into an 8-byte COFF name field.
    /// Short names (<=8) go inline. Long names use string table offset.
    /// is_section: true = "/offset" format, false = zero+offset format.
    void encode_name(std::string_view name, char (&field)[8], bool is_section) noexcept {
        std::memset(field, 0, 8);
        if (name.size() <= COFFI_NAME_SIZE) {
            std::memcpy(field, name.data(), name.size());
            return;
        }
        uint32_t off = add(name);
        if (is_section) {
            // "/123" format
            field[0] = '/';
            auto s = std::to_string(off);
            std::memcpy(field + 1, s.data(), std::min(s.size(), std::size_t{7}));
        } else {
            // Symbol format: 4 zero bytes + 4 LE offset bytes
            uint32_t zero = 0;
            std::memcpy(field, &zero, 4);
            std::memcpy(field + 4, &off, 4);
        }
    }

    [[nodiscard]] const char*  data()  const noexcept { return table_.data(); }
    [[nodiscard]] uint32_t     size()  const noexcept { return static_cast<uint32_t>(table_.size()); }
    [[nodiscard]] bool         empty() const noexcept { return table_.size() <= 4; }

    void clear() noexcept {
        table_.clear();
        table_.resize(4, 0);
        uint32_t sz = 4;
        std::memcpy(table_.data(), &sz, 4);
    }

    [[nodiscard]] std::vector<char> build() const { return table_; }
};

} // namespace coffi
