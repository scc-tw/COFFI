#pragma once

/// coff_editor<Traits> — Full CRUD for COFF/PE files.
/// Owns all data (deep copy). Supports create, load, modify, save.

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

#include <coffi/core/error.hpp>
#include <coffi/core/result.hpp>
#include <coffi/core/byte_view.hpp>
#include <coffi/core/safe_math.hpp>
#include <coffi/platform/schema.hpp>
#include <coffi/platform/traits.hpp>
#include <coffi/editor/section_entry.hpp>
#include <coffi/editor/symbol_entry.hpp>
#include <coffi/editor/string_table_builder.hpp>
#include <coffi/editor/import_builder.hpp>
#include <coffi/editor/layout.hpp>

namespace coffi {

template <typename Traits>
class coff_editor {
    using file_hdr_t = typename Traits::file_header_type;
    using opt_hdr_t  = typename Traits::optional_header_type;
    using win_hdr_t  = typename Traits::win_header_type;
    using sec_t      = section_entry<Traits>;

    file_hdr_t                       coff_hdr_{};
    std::optional<msdos_header>      dos_hdr_;
    std::optional<opt_hdr_t>         opt_hdr_;
    std::optional<win_hdr_t>         win_hdr_;
    std::vector<image_data_directory> dirs_;
    std::vector<sec_t>               sections_;
    std::vector<symbol_entry>        symbols_;
    string_table_builder             strings_;
    import_builder<Traits>           imports_;
    std::vector<char>                dos_stub_;  // between DOS header and PE sig

public:
    // ================================================================
    //  Construction
    // ================================================================

    coff_editor() { std::memset(&coff_hdr_, 0, sizeof(coff_hdr_)); }

    /// Load from byte_view — deep copy all data.
    [[nodiscard]] static result<coff_editor> from_view(byte_view data) noexcept {
        coff_editor ed;
        auto r = ed.load_from(data);
        if (!r) return r.error();
        return ed;
    }

    /// Load from file path.
    [[nodiscard]] static result<coff_editor> from_path(const std::string& path) {
        std::ifstream ifs(path, std::ios::binary | std::ios::ate);
        if (!ifs) return error_code::file_too_small;
        auto sz = static_cast<std::size_t>(ifs.tellg());
        ifs.seekg(0);
        std::vector<char> buf(sz);
        ifs.read(buf.data(), static_cast<std::streamsize>(sz));
        if (!ifs) return error_code::file_too_small;
        return from_view(byte_view{buf.data(), sz});
    }

    // ================================================================
    //  Header access (mutable)
    // ================================================================

    [[nodiscard]] file_hdr_t&       coff_header()       noexcept { return coff_hdr_; }
    [[nodiscard]] const file_hdr_t& coff_header() const noexcept { return coff_hdr_; }

    // --- DOS header (PE only) ---
    [[nodiscard]] bool has_dos_header() const noexcept { return dos_hdr_.has_value(); }
    void create_dos_header() noexcept {
        if constexpr (Traits::has_dos_header) {
            dos_hdr_.emplace();
            std::memset(&*dos_hdr_, 0, sizeof(msdos_header));
            dos_hdr_->signature = static_cast<uint16_t>(PEMAG0)
                                | (static_cast<uint16_t>(PEMAG1) << 8);
            dos_hdr_->pe_sign_location = static_cast<int32_t>(sizeof(msdos_header));
        }
    }
    [[nodiscard]] msdos_header*       dos_header()       noexcept { return dos_hdr_ ? &*dos_hdr_ : nullptr; }
    [[nodiscard]] const msdos_header* dos_header() const noexcept { return dos_hdr_ ? &*dos_hdr_ : nullptr; }

    // DOS stub (data between DOS header and PE signature)
    [[nodiscard]] const std::vector<char>& dos_stub() const noexcept { return dos_stub_; }
    void set_dos_stub(const void* data, std::size_t size) {
        dos_stub_.assign(static_cast<const char*>(data),
                         static_cast<const char*>(data) + size);
        if (dos_hdr_) {
            dos_hdr_->pe_sign_location =
                static_cast<int32_t>(sizeof(msdos_header) + dos_stub_.size());
        }
    }
    void clear_dos_stub() noexcept {
        dos_stub_.clear();
        if (dos_hdr_)
            dos_hdr_->pe_sign_location = static_cast<int32_t>(sizeof(msdos_header));
    }

    // --- Optional header ---
    [[nodiscard]] bool has_optional_header() const noexcept { return opt_hdr_.has_value(); }
    void create_optional_header() noexcept {
        opt_hdr_.emplace();
        std::memset(&*opt_hdr_, 0, sizeof(opt_hdr_t));
        if constexpr (Traits::magic != 0)
            opt_hdr_->magic = Traits::magic;
    }
    void remove_optional_header() noexcept { opt_hdr_.reset(); win_hdr_.reset(); }
    [[nodiscard]] opt_hdr_t*       optional_header()       noexcept { return opt_hdr_ ? &*opt_hdr_ : nullptr; }
    [[nodiscard]] const opt_hdr_t* optional_header() const noexcept { return opt_hdr_ ? &*opt_hdr_ : nullptr; }

    // --- Win header (PE only) ---
    [[nodiscard]] bool has_win_header() const noexcept {
        if constexpr (!Traits::has_win_header) return false;
        else return win_hdr_.has_value();
    }
    void create_win_header() noexcept {
        if constexpr (Traits::has_win_header) {
            win_hdr_.emplace();
            std::memset(&*win_hdr_, 0, sizeof(win_hdr_t));
            win_hdr_->file_alignment = 0x200;
            win_hdr_->section_alignment = 0x1000;
            win_hdr_->number_of_rva_and_sizes = 16;
        }
    }
    template <typename W = win_hdr_t>
    [[nodiscard]] std::enable_if_t<!std::is_same_v<W, typename ti_traits::no_win_header> &&
                                   !std::is_same_v<W, typename ceva_traits::no_win_header>, W*>
    win_header() noexcept { return win_hdr_ ? &*win_hdr_ : nullptr; }

    template <typename W = win_hdr_t>
    [[nodiscard]] std::enable_if_t<!std::is_same_v<W, typename ti_traits::no_win_header> &&
                                   !std::is_same_v<W, typename ceva_traits::no_win_header>, const W*>
    win_header() const noexcept { return win_hdr_ ? &*win_hdr_ : nullptr; }

    // ================================================================
    //  Data directories (PE only)
    // ================================================================

    [[nodiscard]] std::size_t directory_count() const noexcept { return dirs_.size(); }

    void ensure_directories(uint32_t n) {
        if (dirs_.size() < n) dirs_.resize(n, image_data_directory{0, 0});
    }

    [[nodiscard]] image_data_directory* directory(uint32_t i) noexcept {
        if (i >= dirs_.size()) return nullptr;
        return &dirs_[i];
    }

    [[nodiscard]] const image_data_directory* directory(uint32_t i) const noexcept {
        if (i >= dirs_.size()) return nullptr;
        return &dirs_[i];
    }

    void set_directory(uint32_t i, const image_data_directory& d) {
        ensure_directories(i + 1);
        dirs_[i] = d;
    }

    // ================================================================
    //  Section CRUD
    // ================================================================

    [[nodiscard]] std::vector<sec_t>&       sections()       noexcept { return sections_; }
    [[nodiscard]] const std::vector<sec_t>& sections() const noexcept { return sections_; }
    [[nodiscard]] std::size_t section_count()           const noexcept { return sections_.size(); }

    sec_t& add_section(std::string_view name) {
        sections_.emplace_back(name);
        sections_.back().set_index(static_cast<uint32_t>(sections_.size() - 1));
        return sections_.back();
    }

    sec_t& add_section(std::string_view name, uint32_t flags) {
        auto& s = add_section(name);
        s.set_flags(flags);
        return s;
    }

    result<void> remove_section(uint32_t idx) noexcept {
        if (idx >= sections_.size()) return error_code::out_of_bounds;
        sections_.erase(sections_.begin() + idx);
        reindex_sections();
        return {};
    }

    result<void> remove_section(std::string_view name) noexcept {
        auto* s = find_section(name);
        if (!s) return error_code::not_found;
        auto idx = static_cast<uint32_t>(s - sections_.data());
        return remove_section(idx);
    }

    [[nodiscard]] sec_t* find_section(std::string_view name) noexcept {
        for (auto& s : sections_)
            if (s.name() == name) return &s;
        return nullptr;
    }

    [[nodiscard]] const sec_t* find_section(std::string_view name) const noexcept {
        for (auto& s : sections_)
            if (s.name() == name) return &s;
        return nullptr;
    }

    // ================================================================
    //  Symbol CRUD
    // ================================================================

    [[nodiscard]] std::vector<symbol_entry>&       symbols()       noexcept { return symbols_; }
    [[nodiscard]] const std::vector<symbol_entry>& symbols() const noexcept { return symbols_; }
    [[nodiscard]] std::size_t symbol_count()                 const noexcept { return symbols_.size(); }

    symbol_entry& add_symbol(std::string_view name) {
        symbols_.emplace_back(name);
        reindex_symbols();
        return symbols_.back();
    }

    result<void> remove_symbol(uint32_t idx) noexcept {
        if (idx >= symbols_.size()) return error_code::out_of_bounds;
        symbols_.erase(symbols_.begin() + idx);
        reindex_symbols();
        return {};
    }

    [[nodiscard]] symbol_entry* find_symbol(std::string_view name) noexcept {
        for (auto& s : symbols_)
            if (s.name() == name) return &s;
        return nullptr;
    }

    // ================================================================
    //  Import building (PE only)
    // ================================================================

    [[nodiscard]] import_builder<Traits>&       imports()       noexcept { return imports_; }
    [[nodiscard]] const import_builder<Traits>& imports() const noexcept { return imports_; }

    // ================================================================
    //  Save
    // ================================================================

    /// Save to a byte buffer.
    [[nodiscard]] result<std::vector<char>> save() noexcept {
        // 1. Materialize imports
        if constexpr (Traits::has_imports) {
            if (!imports_.empty()) {
                auto r = materialize_imports();
                if (!r) return r.error();
            }
        }

        // 2. Update reloc/line counts in headers
        for (auto& sec : sections_) {
            sec.raw_header().reloc_count = static_cast<decltype(sec.raw_header().reloc_count)>(
                sec.relocations().size());
            sec.raw_header().line_num_count = static_cast<decltype(sec.raw_header().line_num_count)>(
                sec.line_numbers().size());
        }

        // 3. Layout
        auto lr = layout_engine<Traits>::compute(
            coff_hdr_, opt_hdr_ ? &*opt_hdr_ : nullptr,
            dirs_, sections_, symbols_, strings_, has_dos_header());
        if (!lr) return lr.error();

        // 4. Apply file alignment (PE)
        if constexpr (Traits::has_win_header) {
            if (win_hdr_) {
                layout_engine<Traits>::apply_file_alignment(
                    win_hdr_->file_alignment, lr->headers_end, sections_, *lr);
                // Recompute total size
                lr->total_size = lr->symbol_table_off;
                uint32_t sym_slots = 0;
                for (auto& s : symbols_) sym_slots += s.total_slots();
                lr->total_size += sym_slots * static_cast<uint32_t>(sizeof(symbol_record));
                if (!strings_.empty()) lr->total_size += strings_.size();
            }
        }

        // 5. Update header fields
        update_headers(*lr);

        // 6. Write binary
        return write_binary(*lr);
    }

    /// Save to file.
    [[nodiscard]] result<void> save(const std::string& path) {
        auto buf = save();
        if (!buf) return buf.error();
        std::ofstream ofs(path, std::ios::binary);
        if (!ofs) return error_code::write_failed;
        ofs.write(buf->data(), static_cast<std::streamsize>(buf->size()));
        if (!ofs) return error_code::write_failed;
        return {};
    }

    // ================================================================
    //  String table
    // ================================================================

    [[nodiscard]] string_table_builder&       string_table()       noexcept { return strings_; }
    [[nodiscard]] const string_table_builder& string_table() const noexcept { return strings_; }

private:
    // ---- Load from byte_view (deep copy) ----
    result<void> load_from(byte_view data) noexcept {
        std::size_t off = 0;

        // DOS header
        if constexpr (Traits::has_dos_header) {
            if (data.size() >= sizeof(msdos_header)) {
                auto dos = data.read<msdos_header>(0);
                if (dos) {
                    uint8_t s0 = static_cast<uint8_t>(dos->signature & 0xFF);
                    uint8_t s1 = static_cast<uint8_t>(dos->signature >> 8);
                    if (s0 == PEMAG0 && s1 == PEMAG1) {
                        dos_hdr_ = *dos;
                        auto pe_loc = static_cast<std::size_t>(dos->pe_sign_location);
                        if (pe_loc + 4 > data.size()) return error_code::truncated_header;
                        auto pe_sig = data.read<uint32_t>(pe_loc);
                        if (!pe_sig || *pe_sig != PE_SIGNATURE)
                            return error_code::invalid_pe_signature;
                        // DOS stub (between header and PE sig)
                        if (pe_loc > sizeof(msdos_header)) {
                            auto stub_sz = pe_loc - sizeof(msdos_header);
                            dos_stub_.assign(
                                data.as_chars(sizeof(msdos_header)),
                                data.as_chars(sizeof(msdos_header)) + stub_sz);
                        }
                        off = pe_loc + 4;
                    }
                }
            }
        }

        // COFF header
        auto coff = data.read<file_hdr_t>(off);
        if (!coff) return coff.error();
        coff_hdr_ = *coff;
        off += sizeof(file_hdr_t);

        uint16_t opt_sz = 0;
        // Get optional_header_size from the correct field
        if constexpr (std::is_same_v<file_hdr_t, coff_file_header>) {
            opt_sz = coff_hdr_.optional_header_size;
        } else if constexpr (std::is_same_v<file_hdr_t, coff_file_header_ti>) {
            opt_sz = coff_hdr_.optional_header_size;
        }

        // Optional header
        if (opt_sz > 0) {
            auto opt = data.read<opt_hdr_t>(off);
            if (!opt) return opt.error();
            opt_hdr_ = *opt;
            off += sizeof(opt_hdr_t);

            // Win header (PE only)
            if constexpr (Traits::has_win_header) {
                auto win = data.read<win_hdr_t>(off);
                if (!win) return win.error();
                win_hdr_ = *win;
                off += sizeof(win_hdr_t);

                // Data directories
                if constexpr (Traits::has_directories) {
                    uint32_t ndir = win_hdr_->number_of_rva_and_sizes;
                    dirs_.resize(ndir);
                    for (uint32_t i = 0; i < ndir; ++i) {
                        auto d = data.read<image_data_directory>(off);
                        if (!d) return d.error();
                        dirs_[i] = *d;
                        off += sizeof(image_data_directory);
                    }
                }
            }
        }

        // Use opt_sz to determine where sections start
        auto sections_off = (off - sizeof(file_hdr_t)) + sizeof(file_hdr_t) + opt_sz;
        // Actually, sections start right after: coff_header_offset + sizeof(file_hdr_t) + opt_sz
        // We already consumed the opt/win/dirs, so 'off' should be correct if opt_sz matches.
        // But opt_sz might differ from what we consumed. Let's use the original calculation.
        if constexpr (Traits::has_dos_header) {
            if (dos_hdr_) {
                auto pe_loc = static_cast<std::size_t>(dos_hdr_->pe_sign_location);
                sections_off = pe_loc + 4 + sizeof(file_hdr_t) + opt_sz;
            } else {
                sections_off = sizeof(file_hdr_t) + opt_sz;
            }
        } else {
            sections_off = sizeof(file_hdr_t) + opt_sz;
        }

        // Sections
        uint16_t sec_count = 0;
        if constexpr (std::is_same_v<file_hdr_t, coff_file_header>) {
            sec_count = coff_hdr_.sections_count;
        } else if constexpr (std::is_same_v<file_hdr_t, coff_file_header_ti>) {
            sec_count = coff_hdr_.sections_count;
        }

        using sec_hdr_t = typename Traits::section_header_type;
        sections_.resize(sec_count);
        for (uint16_t i = 0; i < sec_count; ++i) {
            auto hdr_off = sections_off + i * sizeof(sec_hdr_t);
            auto hdr = data.read<sec_hdr_t>(hdr_off);
            if (!hdr) return hdr.error();
            sections_[i].raw_header() = *hdr;
            sections_[i].set_index(i);

            // Resolve name
            auto name_ptr = data.as_chars(hdr_off);
            if (name_ptr) {
                // Temporarily build string table for name resolution
                std::size_t len = 0;
                while (len < COFFI_NAME_SIZE && hdr->name[len] != '\0') ++len;
                sections_[i].set_name(std::string_view(hdr->name, len));
                // Long name resolution happens below after loading string table
            }

            // Load section data
            if (hdr->data_size > 0 && hdr->data_offset > 0) {
                auto sv = data.subview(hdr->data_offset, hdr->data_size);
                if (sv) {
                    sections_[i].set_data(
                        reinterpret_cast<const char*>(sv->data()), sv->size());
                }
            }

            // Load relocations
            auto reloc_count_val = hdr->reloc_count;
            if (reloc_count_val > 0 && hdr->reloc_offset > 0) {
                using rel_t = typename Traits::relocation_type;
                for (uint32_t ri = 0; ri < reloc_count_val; ++ri) {
                    auto rel = data.read<rel_t>(hdr->reloc_offset + ri * sizeof(rel_t));
                    if (rel) sections_[i].add_relocation(*rel);
                }
            }
        }

        // Symbol table + string table
        uint32_t sym_table_off = 0, sym_count = 0;
        if constexpr (std::is_same_v<file_hdr_t, coff_file_header>) {
            sym_table_off = coff_hdr_.symbol_table_offset;
            sym_count = coff_hdr_.symbols_count;
        } else if constexpr (std::is_same_v<file_hdr_t, coff_file_header_ti>) {
            sym_table_off = coff_hdr_.symbol_table_offset;
            sym_count = coff_hdr_.symbols_count;
        }

        // Load string table first (needed for name resolution)
        if (sym_table_off > 0 && sym_count > 0) {
            auto str_off_res = checked_mul<std::size_t>(sym_count, sizeof(symbol_record));
            if (str_off_res) {
                auto str_off = checked_add(static_cast<std::size_t>(sym_table_off), *str_off_res);
                if (str_off && *str_off + 4 <= data.size()) {
                    auto str_sz_res = data.read<uint32_t>(*str_off);
                    if (str_sz_res && *str_off + *str_sz_res <= data.size()) {
                        // Load string table into our builder
                        strings_.clear();
                        // We need to copy the raw string table data
                        // For now, load symbols and resolve names using byte_view
                    }
                }
            }
        }

        // Load symbols
        if (sym_table_off > 0 && sym_count > 0) {
            // Build a temporary string table view for name resolution
            auto str_off_res = checked_mul<std::size_t>(sym_count, sizeof(symbol_record));
            byte_view str_view;
            if (str_off_res) {
                auto str_off = checked_add(static_cast<std::size_t>(sym_table_off), *str_off_res);
                if (str_off && *str_off + 4 <= data.size()) {
                    auto str_sz_res = data.read<uint32_t>(*str_off);
                    if (str_sz_res && *str_off + *str_sz_res <= data.size()) {
                        auto sv = data.subview(*str_off, *str_sz_res);
                        if (sv) str_view = *sv;
                    }
                }
            }

            for (uint32_t i = 0; i < sym_count; ) {
                auto rec = data.read<symbol_record>(sym_table_off + i * sizeof(symbol_record));
                if (!rec) break;

                symbol_entry se;
                se.raw_record() = *rec;
                se.set_index(i);

                // Resolve name
                uint32_t first4;
                std::memcpy(&first4, rec->name, 4);
                if (first4 == 0 && !str_view.empty()) {
                    uint32_t name_off;
                    std::memcpy(&name_off, rec->name + 4, 4);
                    auto sv = str_view.read_cstring(name_off);
                    se.set_name(sv);
                } else {
                    std::size_t len = 0;
                    while (len < COFFI_NAME_SIZE && rec->name[len] != '\0') ++len;
                    se.set_name(std::string_view(rec->name, len));
                }

                // Load aux records
                for (uint8_t a = 0; a < rec->aux_symbols_number; ++a) {
                    auto aux = data.read<auxiliary_symbol_record>(
                        sym_table_off + (i + 1 + a) * sizeof(symbol_record));
                    if (aux) se.add_aux(*aux);
                }

                i += 1u + rec->aux_symbols_number;
                symbols_.push_back(std::move(se));
            }

            // Also resolve long section names using string table
            if (!str_view.empty()) {
                for (auto& sec : sections_) {
                    auto& hdr = sec.raw_header();
                    if (hdr.name[0] == '/') {
                        uint32_t name_off = 0;
                        for (int j = 1; j < 8 && hdr.name[j] >= '0' && hdr.name[j] <= '9'; ++j)
                            name_off = name_off * 10 + static_cast<uint32_t>(hdr.name[j] - '0');
                        auto sv = str_view.read_cstring(name_off);
                        if (!sv.empty()) sec.set_name(sv);
                    } else {
                        uint32_t first4;
                        std::memcpy(&first4, hdr.name, 4);
                        if (first4 == 0) {
                            uint32_t name_off;
                            std::memcpy(&name_off, hdr.name + 4, 4);
                            auto sv = str_view.read_cstring(name_off);
                            if (!sv.empty()) sec.set_name(sv);
                        }
                    }
                }
            }
        }

        return {};
    }

    // ---- Materialize imports into .idata section ----
    result<void> materialize_imports() noexcept {
        // Compute next section RVA
        uint32_t next_rva = 0x1000;
        if constexpr (Traits::has_win_header) {
            if (win_hdr_) {
                uint32_t sa = win_hdr_->section_alignment;
                for (auto& sec : sections_) {
                    uint32_t end = sec.virtual_address() + sec.virtual_size();
                    uint32_t aligned = align_to(end, sa);
                    if (aligned > next_rva) next_rva = aligned;
                }
            }
        }

        auto res = imports_.build(next_rva);
        if (!res) return res.error();

        // Create or replace .idata section
        auto* idata = find_section(".idata");
        if (!idata) {
            auto& sec = add_section(".idata",
                SCN_CNT_INITIALIZED_DATA | SCN_MEM_READ);
            idata = &sec;
        }
        idata->set_data(std::move(res->section_data));
        idata->set_virtual_address(next_rva);
        idata->set_virtual_size(static_cast<uint32_t>(idata->data_length()));

        // Update directories
        ensure_directories(16);
        dirs_[DIR_IMPORT] = res->import_dir;
        dirs_[DIR_IAT]    = res->iat_dir;

        return {};
    }

    // ---- Update derived header fields ----
    void update_headers(const layout_result<Traits>& lr) noexcept {
        // COFF header
        if constexpr (std::is_same_v<file_hdr_t, coff_file_header>) {
            coff_hdr_.sections_count = static_cast<uint16_t>(sections_.size());
            uint32_t total_slots = 0;
            for (auto& s : symbols_) total_slots += s.total_slots();
            coff_hdr_.symbols_count = total_slots;
            coff_hdr_.symbol_table_offset = (total_slots > 0) ? lr.symbol_table_off : 0;
            if (opt_hdr_) {
                uint16_t opt_sz = static_cast<uint16_t>(sizeof(opt_hdr_t));
                if constexpr (Traits::has_win_header) {
                    if (win_hdr_) {
                        opt_sz += sizeof(win_hdr_t);
                        opt_sz += static_cast<uint16_t>(dirs_.size() * sizeof(image_data_directory));
                    }
                }
                coff_hdr_.optional_header_size = opt_sz;
            } else {
                coff_hdr_.optional_header_size = 0;
            }
        } else if constexpr (std::is_same_v<file_hdr_t, coff_file_header_ti>) {
            coff_hdr_.sections_count = static_cast<uint16_t>(sections_.size());
            uint32_t total_slots = 0;
            for (auto& s : symbols_) total_slots += s.total_slots();
            coff_hdr_.symbols_count = total_slots;
            coff_hdr_.symbol_table_offset = (total_slots > 0) ? lr.symbol_table_off : 0;
            coff_hdr_.optional_header_size = opt_hdr_
                ? static_cast<uint16_t>(sizeof(opt_hdr_t)) : uint16_t{0};
        }

        // Optional header: compute code/data sizes
        if (opt_hdr_) {
            uint32_t code_sz = 0, init_sz = 0, uninit_sz = 0;
            for (auto& sec : sections_) {
                auto f = sec.flags();
                auto dsz = static_cast<uint32_t>(sec.data_length());
                if (f & SCN_CNT_CODE) code_sz += dsz;
                if (f & SCN_CNT_INITIALIZED_DATA) init_sz += dsz;
                if (f & SCN_CNT_UNINITIALIZED_DATA) uninit_sz += dsz;
            }
            opt_hdr_->code_size = code_sz;
            opt_hdr_->initialized_data_size = init_sz;
            opt_hdr_->uninitialized_data_size = uninit_sz;
        }

        // Win header: image_size, headers_size
        if constexpr (Traits::has_win_header) {
            if (win_hdr_) {
                uint32_t fa = win_hdr_->file_alignment;
                uint32_t sa = win_hdr_->section_alignment;
                win_hdr_->headers_size = align_to(lr.headers_end, fa);
                uint32_t img_sz = align_to(lr.headers_end, sa);
                for (auto& sec : sections_) {
                    img_sz += align_to(sec.virtual_size(), sa);
                }
                win_hdr_->image_size = img_sz;
                win_hdr_->number_of_rva_and_sizes = static_cast<uint32_t>(dirs_.size());
            }
        }
    }

    // ---- Write binary output ----
    result<std::vector<char>> write_binary(const layout_result<Traits>& lr) noexcept {
        std::vector<char> buf(lr.total_size, 0);
        uint32_t pos = 0;

        auto write = [&](const void* src, std::size_t sz) {
            if (pos + sz > buf.size()) buf.resize(pos + sz, 0);
            std::memcpy(buf.data() + pos, src, sz);
            pos += static_cast<uint32_t>(sz);
        };

        // DOS header + PE sig
        if constexpr (Traits::has_dos_header) {
            if (dos_hdr_) {
                write(&*dos_hdr_, sizeof(msdos_header));
                if (!dos_stub_.empty())
                    write(dos_stub_.data(), dos_stub_.size());
                // Pad to pe_sign_location if needed
                auto pe_loc = static_cast<uint32_t>(dos_hdr_->pe_sign_location);
                if (pos < pe_loc) {
                    pos = pe_loc;
                }
                uint32_t pe_sig = PE_SIGNATURE;
                write(&pe_sig, 4);
            }
        }

        // COFF header
        write(&coff_hdr_, sizeof(file_hdr_t));

        // Optional header
        if (opt_hdr_) write(&*opt_hdr_, sizeof(opt_hdr_t));

        // Win header
        if constexpr (Traits::has_win_header) {
            if (win_hdr_) write(&*win_hdr_, sizeof(win_hdr_t));
        }

        // Directories
        if constexpr (Traits::has_directories) {
            for (auto& d : dirs_) write(&d, sizeof(image_data_directory));
        }

        // Section headers
        for (auto& sec : sections_)
            write(&sec.raw_header(), sizeof(typename Traits::section_header_type));

        // Data pages
        for (auto& pg : lr.pages) {
            pos = pg.offset;
            switch (pg.type) {
                case data_page_type::section_data:
                    if (pg.index < sections_.size()) {
                        auto& sec = sections_[pg.index];
                        if (sec.data_length() > 0)
                            std::memcpy(buf.data() + pos, sec.data_ptr(), sec.data_length());
                    }
                    break;
                case data_page_type::relocations:
                    if (pg.index < sections_.size()) {
                        auto& rels = sections_[pg.index].relocations();
                        if (!rels.empty())
                            std::memcpy(buf.data() + pos, rels.data(),
                                        rels.size() * sizeof(typename Traits::relocation_type));
                    }
                    break;
                case data_page_type::line_numbers:
                    if (pg.index < sections_.size()) {
                        auto& lns = sections_[pg.index].line_numbers();
                        if (!lns.empty())
                            std::memcpy(buf.data() + pos, lns.data(),
                                        lns.size() * sizeof(line_number_entry));
                    }
                    break;
                case data_page_type::padding:
                    if (pg.index < lr.padding_blocks.size()) {
                        std::memcpy(buf.data() + pos, lr.padding_blocks[pg.index].data(),
                                    lr.padding_blocks[pg.index].size());
                    }
                    break;
            }
        }

        // Symbol table
        pos = lr.symbol_table_off;
        for (auto& sym : symbols_) {
            sym.raw_record().aux_symbols_number = sym.aux_count();
            std::memcpy(buf.data() + pos, &sym.raw_record(), sizeof(symbol_record));
            pos += sizeof(symbol_record);
            for (auto& aux : sym.aux_records()) {
                std::memcpy(buf.data() + pos, &aux, sizeof(auxiliary_symbol_record));
                pos += sizeof(auxiliary_symbol_record);
            }
        }

        // String table
        if (!strings_.empty()) {
            std::memcpy(buf.data() + pos, strings_.data(), strings_.size());
            pos += strings_.size();
        }

        buf.resize(pos);

        // PE checksum
        if constexpr (Traits::has_win_header) {
            if (win_hdr_) {
                compute_pe_checksum(buf);
            }
        }

        return buf;
    }

    void compute_pe_checksum(std::vector<char>& buf) noexcept {
        if constexpr (!Traits::has_win_header) return;
        // Find checksum field offset
        uint32_t chk_off = 0;
        if (dos_hdr_) {
            chk_off = static_cast<uint32_t>(dos_hdr_->pe_sign_location) + 4;
        }
        chk_off += sizeof(file_hdr_t) + sizeof(opt_hdr_t);
        // checksum is at offset 16 within win_header_pe, offset 20 within win_header_pe_plus
        if constexpr (std::is_same_v<win_hdr_t, win_header_pe>) {
            chk_off += 40; // offsetof(win_header_pe, checksum)
        } else if constexpr (std::is_same_v<win_hdr_t, win_header_pe_plus>) {
            chk_off += 44; // offsetof(win_header_pe_plus, checksum)
        }

        // Zero the checksum field
        if (chk_off + 4 <= buf.size()) {
            uint32_t zero = 0;
            std::memcpy(buf.data() + chk_off, &zero, 4);
        }

        // Compute checksum (sum of all uint16_t words)
        uint64_t chk = 0;
        auto* words = reinterpret_cast<const uint16_t*>(buf.data());
        auto word_count = buf.size() / 2;
        for (std::size_t i = 0; i < word_count; ++i) {
            chk += words[i];
            chk = (chk >> 16) + (chk & 0xFFFF);
        }
        if (buf.size() % 2) {
            chk += static_cast<uint8_t>(buf.back());
            chk = (chk >> 16) + (chk & 0xFFFF);
        }
        chk = ((chk >> 16) + chk) & 0xFFFF;
        chk += buf.size();

        // Patch
        auto chk32 = static_cast<uint32_t>(chk);
        if (chk_off + 4 <= buf.size())
            std::memcpy(buf.data() + chk_off, &chk32, 4);
    }

    void reindex_sections() noexcept {
        for (uint32_t i = 0; i < sections_.size(); ++i)
            sections_[i].set_index(i);
    }

    void reindex_symbols() noexcept {
        uint32_t idx = 0;
        for (auto& s : symbols_) {
            s.set_index(idx);
            idx += s.total_slots();
        }
    }
};

} // namespace coffi
