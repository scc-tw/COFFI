#pragma once

/// Mutable symbol entry — owns symbol record, name, and auxiliary records.

#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>
#include <coffi/platform/schema.hpp>

namespace coffi {

class symbol_entry {
    symbol_record                        record_{};
    std::string                          name_;
    std::vector<auxiliary_symbol_record>  aux_;
    uint32_t                             index_ = 0;

public:
    symbol_entry() { std::memset(&record_, 0, sizeof(record_)); }

    explicit symbol_entry(std::string_view name) : symbol_entry() {
        set_name(name);
    }

    // --- Name ---
    [[nodiscard]] std::string_view name() const noexcept { return name_; }
    void set_name(std::string_view n) { name_ = std::string(n); }

    // --- Field accessors ---
    [[nodiscard]] uint32_t value()          const noexcept { return record_.value; }
    void set_value(uint32_t v)                    noexcept { record_.value = v; }

    [[nodiscard]] uint16_t section_number() const noexcept { return record_.section_number; }
    void set_section_number(uint16_t v)           noexcept { record_.section_number = v; }

    [[nodiscard]] uint16_t type()           const noexcept { return record_.type; }
    void set_type(uint16_t v)                     noexcept { record_.type = v; }

    [[nodiscard]] uint8_t  storage_class()  const noexcept { return record_.storage_class; }
    void set_storage_class(uint8_t v)             noexcept { record_.storage_class = v; }

    [[nodiscard]] uint8_t aux_count() const noexcept {
        return static_cast<uint8_t>(aux_.size());
    }

    // --- Auxiliary records ---
    [[nodiscard]] const std::vector<auxiliary_symbol_record>& aux_records() const noexcept { return aux_; }
    [[nodiscard]]       std::vector<auxiliary_symbol_record>& aux_records()       noexcept { return aux_; }

    void add_aux(const auxiliary_symbol_record& a) { aux_.push_back(a); }
    void clear_aux() noexcept { aux_.clear(); }

    // --- Raw record access ---
    [[nodiscard]] symbol_record&       raw_record()       noexcept { return record_; }
    [[nodiscard]] const symbol_record& raw_record() const noexcept { return record_; }

    // --- Index management ---
    [[nodiscard]] uint32_t index() const noexcept { return index_; }
    void set_index(uint32_t i) noexcept { index_ = i; }

    /// Total symbol table slots consumed: 1 (main) + aux count
    [[nodiscard]] uint32_t total_slots() const noexcept {
        return 1 + static_cast<uint32_t>(aux_.size());
    }
};

} // namespace coffi
