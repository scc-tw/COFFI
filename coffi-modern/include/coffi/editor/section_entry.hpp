#pragma once

/// Mutable section entry — owns header, data, relocations, and line numbers.

#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>
#include <coffi/core/byte_view.hpp>
#include <coffi/platform/schema.hpp>

namespace coffi {

template <typename Traits>
class section_entry {
public:
    using header_type     = typename Traits::section_header_type;
    using relocation_type = typename Traits::relocation_type;

private:
    header_type                    header_{};
    std::string                    name_;
    std::vector<char>              data_;
    std::vector<relocation_type>   relocs_;
    std::vector<line_number_entry> line_nums_;
    uint32_t                       index_ = 0;

public:
    section_entry() { std::memset(&header_, 0, sizeof(header_)); }

    explicit section_entry(std::string_view name) : section_entry() {
        set_name(name);
    }

    // --- Name ---
    [[nodiscard]] std::string_view name() const noexcept { return name_; }
    void set_name(std::string_view n) { name_ = std::string(n); }

    // --- Index ---
    [[nodiscard]] uint32_t index() const noexcept { return index_; }
    void set_index(uint32_t i) noexcept { index_ = i; }

    // --- Header field accessors ---
    [[nodiscard]] uint32_t virtual_size()    const noexcept { return header_.virtual_size; }
    void set_virtual_size(uint32_t v)              noexcept { header_.virtual_size = v; }

    [[nodiscard]] uint32_t virtual_address() const noexcept { return header_.virtual_address; }
    void set_virtual_address(uint32_t v)           noexcept { header_.virtual_address = v; }

    [[nodiscard]] uint32_t data_offset()     const noexcept { return header_.data_offset; }
    void set_data_offset(uint32_t v)               noexcept { header_.data_offset = v; }

    [[nodiscard]] uint32_t reloc_offset()    const noexcept { return header_.reloc_offset; }
    void set_reloc_offset(uint32_t v)              noexcept { header_.reloc_offset = v; }

    [[nodiscard]] uint32_t flags()           const noexcept { return header_.flags; }
    void set_flags(uint32_t f)                     noexcept { header_.flags = f; }

    // --- Data ---
    [[nodiscard]] const char*  data_ptr()    const noexcept { return data_.data(); }
    [[nodiscard]] std::size_t  data_length() const noexcept { return data_.size(); }
    [[nodiscard]] byte_view    data_view()   const noexcept { return {data_.data(), data_.size()}; }

    void set_data(const void* src, std::size_t len) {
        data_.assign(static_cast<const char*>(src), static_cast<const char*>(src) + len);
    }
    void set_data(std::vector<char> d) { data_ = std::move(d); }
    void set_data(std::string_view sv) { data_.assign(sv.begin(), sv.end()); }

    void append_data(const void* src, std::size_t len) {
        auto p = static_cast<const char*>(src);
        data_.insert(data_.end(), p, p + len);
    }
    void clear_data() noexcept { data_.clear(); }

    // --- Relocations ---
    [[nodiscard]] const std::vector<relocation_type>& relocations() const noexcept { return relocs_; }
    [[nodiscard]]       std::vector<relocation_type>& relocations()       noexcept { return relocs_; }
    void add_relocation(const relocation_type& r) { relocs_.push_back(r); }
    void clear_relocations() noexcept { relocs_.clear(); }

    [[nodiscard]] uint32_t relocations_file_size() const noexcept {
        return static_cast<uint32_t>(relocs_.size() * sizeof(relocation_type));
    }

    // --- Line numbers ---
    [[nodiscard]] const std::vector<line_number_entry>& line_numbers() const noexcept { return line_nums_; }
    [[nodiscard]]       std::vector<line_number_entry>& line_numbers()       noexcept { return line_nums_; }
    void add_line_number(const line_number_entry& ln) { line_nums_.push_back(ln); }
    void clear_line_numbers() noexcept { line_nums_.clear(); }

    [[nodiscard]] uint32_t line_numbers_file_size() const noexcept {
        return static_cast<uint32_t>(line_nums_.size() * sizeof(line_number_entry));
    }

    // --- Convenience flags ---
    [[nodiscard]] bool is_code() const noexcept { return flags() & SCN_CNT_CODE; }
    [[nodiscard]] bool is_data() const noexcept { return flags() & SCN_CNT_INITIALIZED_DATA; }
    [[nodiscard]] bool is_bss()  const noexcept { return flags() & SCN_CNT_UNINITIALIZED_DATA; }

    // --- Raw header access (for layout engine / serialization) ---
    [[nodiscard]] header_type&       raw_header()       noexcept { return header_; }
    [[nodiscard]] const header_type& raw_header() const noexcept { return header_; }

    // --- TI-specific (guarded at compile time) ---
    template <typename H = header_type>
    [[nodiscard]] std::enable_if_t<std::is_same_v<H, section_header_ti>, uint32_t>
    physical_address() const noexcept { return header_.physical_address; }

    template <typename H = header_type>
    std::enable_if_t<std::is_same_v<H, section_header_ti>>
    set_physical_address(uint32_t v) noexcept { header_.physical_address = v; }

    template <typename H = header_type>
    [[nodiscard]] std::enable_if_t<std::is_same_v<H, section_header_ti>, uint16_t>
    page_number() const noexcept { return header_.page_number; }

    template <typename H = header_type>
    std::enable_if_t<std::is_same_v<H, section_header_ti>>
    set_page_number(uint16_t v) noexcept { header_.page_number = v; }
};

} // namespace coffi
