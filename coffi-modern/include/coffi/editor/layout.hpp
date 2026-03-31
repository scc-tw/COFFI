#pragma once

/// Two-pass layout engine.
/// Computes file offsets, applies PE file alignment, and derives header fields.
/// Adapted from original COFFI's layout() / populate_data_pages() / compute_offsets().

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <type_traits>
#include <vector>
#include <coffi/core/error.hpp>
#include <coffi/core/result.hpp>
#include <coffi/core/safe_math.hpp>
#include <coffi/editor/section_entry.hpp>
#include <coffi/editor/symbol_entry.hpp>
#include <coffi/editor/string_table_builder.hpp>
#include <coffi/platform/schema.hpp>

namespace coffi {

enum class data_page_type : uint8_t {
    section_data, relocations, line_numbers, padding
};

struct data_page {
    data_page_type type;
    uint32_t       offset = 0;
    uint32_t       size   = 0;
    uint32_t       index  = 0;
};

template <typename Traits>
struct layout_result {
    uint32_t headers_end     = 0;
    uint32_t symbol_table_off = 0;
    uint32_t total_size      = 0;
    std::vector<data_page>         pages;
    std::vector<std::vector<char>> padding_blocks;
};

template <typename Traits>
class layout_engine {
    using sec_t = section_entry<Traits>;

public:
    [[nodiscard]] static result<layout_result<Traits>> compute(
        typename Traits::file_header_type&      coff_hdr,
        typename Traits::optional_header_type*   opt_hdr,
        std::vector<image_data_directory>&       dirs,
        std::vector<sec_t>&                      sections,
        std::vector<symbol_entry>&               symbols,
        string_table_builder&                    strings,
        bool has_dos
    ) noexcept {
        layout_result<Traits> lr;

        // --- Encode names into string table ---
        strings.clear();
        for (auto& sec : sections)
            strings.encode_name(sec.name(), sec.raw_header().name, true);
        for (auto& sym : symbols)
            strings.encode_name(sym.name(), sym.raw_record().name, false);

        // --- Compute header end offset ---
        lr.headers_end = compute_headers_end(coff_hdr, opt_hdr, dirs, sections, has_dos);

        // --- First pass: populate + compute ---
        populate(sections, lr.pages);
        compute_offsets(lr.headers_end, sections, lr.pages, lr.symbol_table_off);

        // --- Apply file alignment (PE only) ---
        if constexpr (Traits::has_win_header) {
            // We need the win header to get file_alignment. It's right after opt_hdr.
            // The caller should have placed it there. We read file_alignment from the
            // win header bytes that follow the optional header in the coff_editor.
            // For now, we handle this via a second call path in coff_editor.
        }

        // --- Compute total size ---
        lr.total_size = lr.symbol_table_off;
        // Add symbol table size
        uint32_t sym_slots = 0;
        for (auto& s : symbols) sym_slots += s.total_slots();
        lr.total_size += sym_slots * sizeof(symbol_record);
        // Add string table
        if (!strings.empty())
            lr.total_size += strings.size();

        return lr;
    }

    /// Apply file alignment padding (PE-specific, called by coff_editor)
    static void apply_file_alignment(
        uint32_t file_alignment,
        uint32_t headers_end,
        std::vector<sec_t>& sections,
        layout_result<Traits>& lr
    ) noexcept {
        if (file_alignment == 0) return;

        lr.padding_blocks.clear();
        lr.pages.clear();
        populate(sections, lr.pages);

        // Insert padding between data pages to align to file_alignment
        std::vector<data_page> new_pages;
        uint32_t current_off = align_to(headers_end, file_alignment);

        for (auto& page : lr.pages) {
            // Align current offset
            uint32_t aligned = align_to(current_off, file_alignment);
            if (aligned > current_off) {
                // Add padding
                auto pad_size = aligned - current_off;
                auto pad_idx = static_cast<uint32_t>(lr.padding_blocks.size());
                lr.padding_blocks.emplace_back(pad_size, '\0');
                new_pages.push_back({data_page_type::padding, current_off, pad_size, pad_idx});
                current_off = aligned;
            }
            page.offset = current_off;
            new_pages.push_back(page);
            current_off += page.size;
        }

        lr.pages = std::move(new_pages);

        // Recompute offsets with padding
        compute_offsets_from_pages(sections, lr.pages, lr.symbol_table_off);
    }

private:
    static uint32_t compute_headers_end(
        const typename Traits::file_header_type& coff_hdr,
        const typename Traits::optional_header_type* opt_hdr,
        const std::vector<image_data_directory>& dirs,
        const std::vector<sec_t>& sections,
        bool has_dos
    ) noexcept {
        uint32_t off = 0;
        if constexpr (Traits::has_dos_header) {
            if (has_dos) off += sizeof(msdos_header) + 4; // DOS header + PE sig
        }
        off += sizeof(typename Traits::file_header_type);
        if (opt_hdr) {
            off += sizeof(typename Traits::optional_header_type);
            if constexpr (Traits::has_win_header) {
                off += sizeof(typename Traits::win_header_type);
            }
        }
        if constexpr (Traits::has_directories) {
            off += static_cast<uint32_t>(dirs.size() * sizeof(image_data_directory));
        }
        off += static_cast<uint32_t>(sections.size() * sizeof(typename Traits::section_header_type));
        return off;
    }

    static void populate(const std::vector<sec_t>& sections,
                         std::vector<data_page>& pages) noexcept {
        pages.clear();
        for (uint32_t i = 0; i < sections.size(); ++i) {
            auto& sec = sections[i];
            if (sec.data_length() > 0) {
                pages.push_back({data_page_type::section_data, 0,
                                 static_cast<uint32_t>(sec.data_length()), i});
            }
            if (sec.relocations_file_size() > 0) {
                pages.push_back({data_page_type::relocations, 0,
                                 sec.relocations_file_size(), i});
            }
            if (sec.line_numbers_file_size() > 0) {
                pages.push_back({data_page_type::line_numbers, 0,
                                 sec.line_numbers_file_size(), i});
            }
        }
    }

    static void compute_offsets(uint32_t start,
                                std::vector<sec_t>& sections,
                                std::vector<data_page>& pages,
                                uint32_t& sym_table_off) noexcept {
        uint32_t off = start;
        for (auto& pg : pages) {
            pg.offset = off;
            auto idx = pg.index;
            if (idx < sections.size()) {
                switch (pg.type) {
                    case data_page_type::section_data:
                        sections[idx].set_data_offset(off);
                        sections[idx].raw_header().data_size =
                            static_cast<uint32_t>(sections[idx].data_length());
                        break;
                    case data_page_type::relocations:
                        sections[idx].set_reloc_offset(off);
                        break;
                    case data_page_type::line_numbers:
                        sections[idx].raw_header().line_num_offset = off;
                        break;
                    default: break;
                }
            }
            off += pg.size;
        }
        sym_table_off = off;
    }

    static void compute_offsets_from_pages(
        std::vector<sec_t>& sections,
        const std::vector<data_page>& pages,
        uint32_t& sym_table_off
    ) noexcept {
        uint32_t last_end = 0;
        for (auto& pg : pages) {
            auto idx = pg.index;
            if (pg.type != data_page_type::padding && idx < sections.size()) {
                switch (pg.type) {
                    case data_page_type::section_data:
                        sections[idx].set_data_offset(pg.offset);
                        sections[idx].raw_header().data_size =
                            static_cast<uint32_t>(sections[idx].data_length());
                        break;
                    case data_page_type::relocations:
                        sections[idx].set_reloc_offset(pg.offset);
                        break;
                    case data_page_type::line_numbers:
                        sections[idx].raw_header().line_num_offset = pg.offset;
                        break;
                    default: break;
                }
            }
            auto end = pg.offset + pg.size;
            if (end > last_end) last_end = end;
        }
        sym_table_off = last_end;
    }
};

} // namespace coffi
