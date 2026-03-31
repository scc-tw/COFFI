#pragma once

/// Compile-time architecture traits — the core of TMP-based polymorphism.
///
///   coff_file<pe32_traits>      — 32-bit PE
///   coff_file<pe32plus_traits>  — 64-bit PE (PE32+)
///   coff_editor<ti_traits>      — Texas Instruments COFF
///   coff_editor<ceva_traits>    — CEVA COFF

#include <cstdint>
#include <cstddef>
#include <coffi/platform/schema.hpp>

namespace coffi {

// ================================================================
//  PE32 traits
// ================================================================

struct pe32_traits {
    using file_header_type      = coff_file_header;
    using address_type          = uint32_t;
    using optional_header_type  = coff_optional_header_pe;
    using win_header_type       = win_header_pe;
    using section_header_type   = section_header;
    using relocation_type       = rel_entry;

    static constexpr uint16_t    magic          = OH_MAGIC_PE32;
    static constexpr uint64_t    ordinal_flag   = 1ULL << 31;
    static constexpr std::size_t thunk_size     = 4;
    static constexpr bool        has_data_base  = true;
    static constexpr bool        has_dos_header = true;
    static constexpr bool        has_win_header = true;
    static constexpr bool        has_imports    = true;
    static constexpr bool        has_directories = true;

    [[nodiscard]] static constexpr uint8_t addressable_unit(uint16_t) noexcept { return 1; }
};

// ================================================================
//  PE32+ traits
// ================================================================

struct pe32plus_traits {
    using file_header_type      = coff_file_header;
    using address_type          = uint64_t;
    using optional_header_type  = coff_optional_header_pe_plus;
    using win_header_type       = win_header_pe_plus;
    using section_header_type   = section_header;
    using relocation_type       = rel_entry;

    static constexpr uint16_t    magic          = OH_MAGIC_PE32PLUS;
    static constexpr uint64_t    ordinal_flag   = 1ULL << 63;
    static constexpr std::size_t thunk_size     = 8;
    static constexpr bool        has_data_base  = false;
    static constexpr bool        has_dos_header = true;
    static constexpr bool        has_win_header = true;
    static constexpr bool        has_imports    = true;
    static constexpr bool        has_directories = true;

    [[nodiscard]] static constexpr uint8_t addressable_unit(uint16_t) noexcept { return 1; }
};

// ================================================================
//  Texas Instruments COFF traits
// ================================================================

struct ti_traits {
    using file_header_type      = coff_file_header_ti;
    using address_type          = uint32_t;
    using optional_header_type  = common_optional_header_ti;
    using section_header_type   = section_header_ti;
    using relocation_type       = rel_entry_ti;

    // TI has no Win header — sentinel type
    struct no_win_header {};
    using win_header_type       = no_win_header;

    static constexpr uint16_t    magic          = 0;
    static constexpr uint64_t    ordinal_flag   = 0;
    static constexpr std::size_t thunk_size     = 0;
    static constexpr bool        has_data_base  = true;
    static constexpr bool        has_dos_header = false;
    static constexpr bool        has_win_header = false;
    static constexpr bool        has_imports    = false;
    static constexpr bool        has_directories = false;

    [[nodiscard]] static constexpr uint8_t addressable_unit(uint16_t target_id) noexcept {
        switch (target_id) {
            case TI_TMS320C5400:
            case TI_TMS320C5500:
            case TI_TMS320C2800:
            case TI_TMS320C5500PLUS:
                return 2;
            default:
                return 1;
        }
    }
};

// ================================================================
//  CEVA COFF traits
// ================================================================

struct ceva_traits {
    using file_header_type      = coff_file_header;  // same as PE
    using address_type          = uint32_t;
    using optional_header_type  = coff_optional_header_pe;
    using section_header_type   = section_header;    // same as PE
    using relocation_type       = rel_entry_ceva;

    struct no_win_header {};
    using win_header_type       = no_win_header;

    static constexpr uint16_t    magic          = OH_MAGIC_PE32;
    static constexpr uint64_t    ordinal_flag   = 0;
    static constexpr std::size_t thunk_size     = 0;
    static constexpr bool        has_data_base  = true;
    static constexpr bool        has_dos_header = false;
    static constexpr bool        has_win_header = false;
    static constexpr bool        has_imports    = false;
    static constexpr bool        has_directories = false;

    [[nodiscard]] static constexpr uint8_t addressable_unit(uint16_t) noexcept { return 1; }
};

// ================================================================
//  Architecture detection
// ================================================================

enum class detected_arch : uint8_t {
    unknown   = 0,
    pe32      = 1,
    pe32plus  = 2,
    ti        = 3,
    ceva      = 4,
};

} // namespace coffi
