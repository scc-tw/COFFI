#pragma once

/// Safe RVA (Relative Virtual Address) to file-offset resolver.
/// Iterates section headers to map virtual addresses to raw file positions.
/// All arithmetic uses checked_add / checked_mul to prevent overflows
/// (addresses 1ee0be8 audit: integer overflow in RVA calculations).

#include <cstddef>
#include <cstdint>
#include <coffi/core/byte_view.hpp>
#include <coffi/core/safe_math.hpp>
#include <coffi/platform/schema.hpp>

namespace coffi {

class rva_resolver {
    byte_view   file_data_;
    std::size_t sections_offset_ = 0;
    uint16_t    section_count_   = 0;

public:
    rva_resolver() noexcept = default;

    rva_resolver(byte_view file_data, std::size_t sections_offset, uint16_t count) noexcept
        : file_data_(file_data), sections_offset_(sections_offset), section_count_(count) {}

    /// Convert RVA to file offset. Returns error if RVA doesn't fall in any section.
    [[nodiscard]] result<std::size_t> resolve(uint32_t rva,
                                              std::size_t size_required = 1) const noexcept
    {
        for (uint16_t i = 0; i < section_count_; ++i) {
            auto hdr_off = checked_add(sections_offset_,
                                       static_cast<std::size_t>(i) * sizeof(section_header));
            if (!hdr_off) continue;

            auto hdr = file_data_.read<section_header>(*hdr_off);
            if (!hdr) continue;

            uint32_t sec_va   = hdr->virtual_address;
            uint32_t sec_vsize = hdr->virtual_size;
            if (sec_vsize == 0) sec_vsize = hdr->data_size;  // fallback

            // Check: rva >= sec_va && (rva - sec_va) < sec_vsize
            // Using subtraction to avoid uint32_t overflow (1ee0be8 finding).
            if (rva < sec_va) continue;
            uint32_t delta = rva - sec_va;
            if (delta >= sec_vsize) continue;

            // Verify requested range fits within section's raw data
            auto end_in_section = checked_add(static_cast<std::size_t>(delta), size_required);
            if (!end_in_section || *end_in_section > hdr->data_size)
                return error_code::out_of_bounds;

            auto file_offset = checked_add(static_cast<std::size_t>(hdr->data_offset),
                                           static_cast<std::size_t>(delta));
            if (!file_offset) return error_code::overflow;
            return *file_offset;
        }
        return error_code::invalid_rva;
    }

    /// Resolve RVA and return a byte_view of the requested size.
    [[nodiscard]] result<byte_view> to_view(uint32_t rva,
                                            std::size_t size_required) const noexcept
    {
        auto off = resolve(rva, size_required);
        if (!off) return off.error();
        return file_data_.subview(*off, size_required);
    }

    /// Read a null-terminated string at the given RVA.
    [[nodiscard]] result<std::string_view> read_string(uint32_t rva) const noexcept {
        // First resolve to verify the RVA is valid
        auto off = resolve(rva, 1);
        if (!off) return off.error();

        // Find containing section to bound the string length
        for (uint16_t i = 0; i < section_count_; ++i) {
            auto hdr_off = checked_add(sections_offset_,
                                       static_cast<std::size_t>(i) * sizeof(section_header));
            if (!hdr_off) continue;
            auto hdr = file_data_.read<section_header>(*hdr_off);
            if (!hdr) continue;

            if (rva >= hdr->virtual_address &&
                (rva - hdr->virtual_address) < hdr->data_size)
            {
                auto max_len = hdr->data_size - (rva - hdr->virtual_address);
                return file_data_.read_cstring(*off, max_len);
            }
        }
        return error_code::invalid_rva;
    }
};

} // namespace coffi
