#pragma once

/// Lazy, zero-allocation section views.
///
///   section_ref<Traits>   — lightweight proxy to a single section header
///   section_range<Traits> — iterable range over all sections
///
/// No memory is allocated. Fields are read on demand via memcpy from the
/// underlying byte_view (the entire file buffer).

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string_view>
#include <coffi/core/byte_view.hpp>
#include <coffi/platform/schema.hpp>
#include <coffi/views/string_table.hpp>

namespace coffi {

// ================================================================
//  section_ref — proxy to one section header
// ================================================================

template <typename Traits>
class section_ref {
    byte_view                  file_;
    std::size_t                offset_;
    const string_table_view*   strings_;

public:
    using header_type = typename Traits::section_header_type;

    section_ref(byte_view file, std::size_t offset,
                const string_table_view* str = nullptr) noexcept
        : file_(file), offset_(offset), strings_(str) {}

    [[nodiscard]] result<header_type> header() const noexcept {
        return file_.read<header_type>(offset_);
    }

    [[nodiscard]] std::string_view name() const noexcept {
        // Read name directly from file buffer (not from a local copy)
        // to ensure the returned string_view remains valid.
        auto ptr = file_.as_chars(offset_);
        if (!ptr || offset_ + COFFI_NAME_SIZE > file_.size()) return {};
        if (strings_) return strings_->resolve_name(ptr);
        std::size_t len = 0;
        while (len < COFFI_NAME_SIZE && ptr[len] != '\0') ++len;
        return {ptr, len};
    }

    [[nodiscard]] uint32_t virtual_size()    const noexcept { auto h = header(); return h ? h->virtual_size      : 0; }
    [[nodiscard]] uint32_t virtual_address() const noexcept { auto h = header(); return h ? h->virtual_address  : 0; }
    [[nodiscard]] uint32_t data_size()       const noexcept { auto h = header(); return h ? h->data_size        : 0; }
    [[nodiscard]] uint32_t data_offset()     const noexcept { auto h = header(); return h ? h->data_offset      : 0; }
    [[nodiscard]] uint32_t reloc_offset()    const noexcept { auto h = header(); return h ? h->reloc_offset     : 0; }
    [[nodiscard]] uint32_t line_num_offset() const noexcept { auto h = header(); return h ? h->line_num_offset  : 0; }
    [[nodiscard]] uint32_t flags()           const noexcept { auto h = header(); return h ? h->flags            : 0; }
    [[nodiscard]] uint16_t reloc_count()     const noexcept { auto h = header(); return h ? h->reloc_count      : 0; }
    [[nodiscard]] uint16_t line_num_count()  const noexcept { auto h = header(); return h ? h->line_num_count   : 0; }

    /// Zero-copy view of this section's raw data.
    [[nodiscard]] byte_view data() const noexcept {
        auto h = header();
        if (!h || h->data_size == 0) return {};
        auto v = file_.subview(h->data_offset, h->data_size);
        return v ? *v : byte_view{};
    }

    /// Read the i-th relocation entry.
    [[nodiscard]] result<typename Traits::relocation_type> relocation(uint32_t i) const noexcept {
        auto h = header();
        if (!h || i >= h->reloc_count) return error_code::out_of_bounds;
        auto off = static_cast<std::size_t>(h->reloc_offset)
                 + static_cast<std::size_t>(i) * sizeof(typename Traits::relocation_type);
        return file_.template read<typename Traits::relocation_type>(off);
    }

    /// Read the i-th line number entry.
    [[nodiscard]] result<line_number_entry> line_number(uint32_t i) const noexcept {
        auto h = header();
        if (!h || i >= h->line_num_count) return error_code::out_of_bounds;
        auto off = static_cast<std::size_t>(h->line_num_offset)
                 + static_cast<std::size_t>(i) * sizeof(line_number_entry);
        return file_.template read<line_number_entry>(off);
    }

    // Convenience flags
    [[nodiscard]] bool is_code()       const noexcept { return (flags() & SCN_CNT_CODE) != 0; }
    [[nodiscard]] bool is_data()       const noexcept { return (flags() & SCN_CNT_INITIALIZED_DATA) != 0; }
    [[nodiscard]] bool is_bss()        const noexcept { return (flags() & SCN_CNT_UNINITIALIZED_DATA) != 0; }
    [[nodiscard]] bool is_readable()   const noexcept { return (flags() & SCN_MEM_READ) != 0; }
    [[nodiscard]] bool is_writable()   const noexcept { return (flags() & SCN_MEM_WRITE) != 0; }
    [[nodiscard]] bool is_executable() const noexcept { return (flags() & SCN_MEM_EXECUTE) != 0; }
};

// ================================================================
//  section_range — lazy iterable over all section headers
// ================================================================

template <typename Traits>
class section_range {
    byte_view                file_;
    std::size_t              first_;
    uint16_t                 count_;
    const string_table_view* strings_;

public:
    class iterator {
        byte_view                data_;
        std::size_t              offset_;
        uint16_t                 index_;
        const string_table_view* strings_;

    public:
        using difference_type   = std::ptrdiff_t;
        using value_type        = section_ref<Traits>;
        using pointer           = void;
        using reference         = value_type;
        using iterator_category = std::input_iterator_tag;

        iterator(byte_view d, std::size_t off, uint16_t idx,
                 const string_table_view* s) noexcept
            : data_(d), offset_(off), index_(idx), strings_(s) {}

        value_type operator*() const { return {data_, offset_, strings_}; }
        iterator& operator++() {
            offset_ += sizeof(typename Traits::section_header_type);
            ++index_;
            return *this;
        }
        iterator operator++(int) { auto t = *this; ++(*this); return t; }
        bool operator==(const iterator& o) const noexcept { return index_ == o.index_; }
        bool operator!=(const iterator& o) const noexcept { return index_ != o.index_; }
    };

    section_range(byte_view data, std::size_t first, uint16_t count,
                  const string_table_view* strings = nullptr) noexcept
        : file_(data), first_(first), count_(count), strings_(strings) {}

    [[nodiscard]] iterator    begin() const { return {file_, first_, 0, strings_}; }
    [[nodiscard]] iterator    end()   const { return {file_, 0, count_, strings_}; }
    [[nodiscard]] std::size_t size()  const noexcept { return count_; }
    [[nodiscard]] bool        empty() const noexcept { return count_ == 0; }

    [[nodiscard]] section_ref<Traits> operator[](uint16_t i) const noexcept {
        return {file_, first_ + i * sizeof(typename Traits::section_header_type), strings_};
    }
};

} // namespace coffi
