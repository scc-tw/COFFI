#pragma once

/// Compile-time architecture traits — the core of our TMP-based polymorphism.
/// Replaces virtual functions with template parameters.
///
///   coff_file<pe32_traits>      — 32-bit PE
///   coff_file<pe32plus_traits>  — 64-bit PE (PE32+)

#include <cstdint>
#include <cstddef>
#include <coffi/platform/schema.hpp>

namespace coffi {

struct pe32_traits {
    using address_type          = uint32_t;
    using optional_header_type  = coff_optional_header_pe;
    using win_header_type       = win_header_pe;
    using section_header_type   = section_header;
    using relocation_type       = rel_entry;

    static constexpr uint16_t    magic        = OH_MAGIC_PE32;
    static constexpr uint64_t    ordinal_flag = 1ULL << 31;
    static constexpr std::size_t thunk_size   = 4;
    static constexpr bool        has_data_base = true;
};

struct pe32plus_traits {
    using address_type          = uint64_t;
    using optional_header_type  = coff_optional_header_pe_plus;
    using win_header_type       = win_header_pe_plus;
    using section_header_type   = section_header;
    using relocation_type       = rel_entry;

    static constexpr uint16_t    magic        = OH_MAGIC_PE32PLUS;
    static constexpr uint64_t    ordinal_flag = 1ULL << 63;
    static constexpr std::size_t thunk_size   = 8;
    static constexpr bool        has_data_base = false;
};

// Architecture auto-detection result
enum class detected_arch : uint8_t {
    unknown   = 0,
    pe32      = 1,
    pe32plus  = 2,
};

} // namespace coffi
