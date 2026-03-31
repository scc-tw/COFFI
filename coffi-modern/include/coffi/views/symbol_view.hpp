#pragma once

/// Zero-allocation symbol table views.
///
///   symbol_ref   — proxy to one symbol_record, resolves names via string table
///   symbol_range — iterable range that auto-skips auxiliary symbol records

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string_view>
#include <coffi/core/byte_view.hpp>
#include <coffi/platform/schema.hpp>
#include <coffi/views/string_table.hpp>

namespace coffi {

// ================================================================
//  symbol_ref — proxy to one symbol_record
// ================================================================

class symbol_ref {
    byte_view                file_;
    std::size_t              offset_;
    const string_table_view* strings_;

public:
    symbol_ref(byte_view file, std::size_t offset,
               const string_table_view* str) noexcept
        : file_(file), offset_(offset), strings_(str) {}

    [[nodiscard]] result<symbol_record> record() const noexcept {
        return file_.read<symbol_record>(offset_);
    }

    [[nodiscard]] std::string_view name() const noexcept {
        // Read name directly from file buffer to avoid dangling string_view
        // into a local memcpy'd copy.
        auto ptr = file_.as_chars(offset_);
        if (!ptr || !strings_ || offset_ + COFFI_NAME_SIZE > file_.size()) return {};
        return strings_->resolve_name(ptr);
    }

    [[nodiscard]] uint32_t value()          const noexcept { auto r = record(); return r ? r->value             : 0; }
    [[nodiscard]] uint16_t section_number() const noexcept { auto r = record(); return r ? r->section_number    : 0; }
    [[nodiscard]] uint16_t type()           const noexcept { auto r = record(); return r ? r->type              : 0; }
    [[nodiscard]] uint8_t  storage_class()  const noexcept { auto r = record(); return r ? r->storage_class     : 0; }
    [[nodiscard]] uint8_t  aux_count()      const noexcept { auto r = record(); return r ? r->aux_symbols_number : 0; }

    [[nodiscard]] std::size_t file_offset() const noexcept { return offset_; }
};

// ================================================================
//  symbol_range — lazy range, auto-skips auxiliary records
// ================================================================

class symbol_range {
    byte_view                file_;
    std::size_t              table_offset_;
    uint32_t                 total_;   // includes auxiliary records
    const string_table_view* strings_;

public:
    class iterator {
        byte_view                data_;
        std::size_t              offset_;
        uint32_t                 remaining_;
        const string_table_view* strings_;

    public:
        using difference_type   = std::ptrdiff_t;
        using value_type        = symbol_ref;
        using pointer           = void;
        using reference         = value_type;
        using iterator_category = std::input_iterator_tag;

        iterator(byte_view d, std::size_t off, uint32_t rem,
                 const string_table_view* s) noexcept
            : data_(d), offset_(off), remaining_(rem), strings_(s) {}

        value_type operator*() const { return {data_, offset_, strings_}; }

        iterator& operator++() {
            auto rec = data_.read<symbol_record>(offset_);
            uint32_t skip = 1;
            if (rec) skip += rec->aux_symbols_number;
            offset_ += skip * sizeof(symbol_record);
            remaining_ = (remaining_ > skip) ? (remaining_ - skip) : 0;
            return *this;
        }
        iterator operator++(int) { auto t = *this; ++(*this); return t; }

        bool operator==(const iterator& o) const noexcept { return remaining_ == o.remaining_; }
        bool operator!=(const iterator& o) const noexcept { return remaining_ != o.remaining_; }
    };

    symbol_range(byte_view data, std::size_t table_off, uint32_t count,
                 const string_table_view* strings) noexcept
        : file_(data), table_offset_(table_off), total_(count), strings_(strings) {}

    [[nodiscard]] iterator begin() const { return {file_, table_offset_, total_, strings_}; }
    [[nodiscard]] iterator end()   const { return {file_, 0, 0, strings_}; }
    [[nodiscard]] uint32_t count() const noexcept { return total_; }
    [[nodiscard]] bool     empty() const noexcept { return total_ == 0; }
};

} // namespace coffi
