#pragma once

#include <cstdint>
#include <string_view>

namespace coffi {

/// All error codes returned by coffi-modern APIs.
enum class error_code : uint32_t {
    success = 0,
    out_of_bounds,
    invalid_magic,
    invalid_pe_signature,
    truncated_header,
    overflow,
    invalid_alignment,
    invalid_rva,
    invalid_section_index,
    invalid_symbol_index,
    malformed_string_table,
    malformed_import_table,
    unsupported_architecture,
    division_by_zero,
    file_too_small,
};

constexpr std::string_view to_string(error_code ec) noexcept {
    switch (ec) {
        case error_code::success:                  return "success";
        case error_code::out_of_bounds:            return "access out of bounds";
        case error_code::invalid_magic:            return "invalid magic number";
        case error_code::invalid_pe_signature:     return "invalid PE signature";
        case error_code::truncated_header:         return "truncated header";
        case error_code::overflow:                 return "integer overflow";
        case error_code::invalid_alignment:        return "invalid alignment value";
        case error_code::invalid_rva:              return "invalid RVA";
        case error_code::invalid_section_index:    return "invalid section index";
        case error_code::invalid_symbol_index:     return "invalid symbol index";
        case error_code::malformed_string_table:   return "malformed string table";
        case error_code::malformed_import_table:   return "malformed import table";
        case error_code::unsupported_architecture: return "unsupported architecture";
        case error_code::division_by_zero:         return "division by zero";
        case error_code::file_too_small:           return "file too small";
    }
    return "unknown error";
}

} // namespace coffi
