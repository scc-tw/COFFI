#pragma once

/// coffi-modern — Modern C++17 header-only COFF/PE parser.
///
/// Top-level entry point. Provides:
///   coff_file<Traits>          — template-based PE parser (zero virtual functions)
///   detect_architecture()      — auto-detect PE32 vs PE32+
///   auto_load()                — returns std::variant of PE32 / PE32+ file
///
/// Usage:
///   #include <coffi/coffi.hpp>
///
///   std::vector<char> buf = read_file("notepad.exe");
///   coffi::byte_view  data(buf.data(), buf.size());
///   auto file = coffi::coff_file<coffi::pe32plus_traits>::from_view(data);
///   if (!file) { /* handle error */ }
///   for (auto sec : file->sections()) {
///       std::cout << sec.name() << "\n";
///   }

// Core
#include <coffi/core/error.hpp>
#include <coffi/core/result.hpp>
#include <coffi/core/safe_math.hpp>
#include <coffi/core/endian.hpp>
#include <coffi/core/byte_view.hpp>
#include <coffi/core/lazy.hpp>

// Platform
#include <coffi/platform/schema.hpp>
#include <coffi/platform/traits.hpp>

// Views
#include <coffi/views/string_table.hpp>
#include <coffi/views/rva_resolver.hpp>
#include <coffi/views/section_view.hpp>
#include <coffi/views/symbol_view.hpp>
#include <coffi/views/import_view.hpp>

// Editor (mutable CRUD layer)
#include <coffi/editor/data_builder.hpp>
#include <coffi/editor/string_table_builder.hpp>
#include <coffi/editor/section_entry.hpp>
#include <coffi/editor/symbol_entry.hpp>
#include <coffi/editor/import_builder.hpp>
#include <coffi/editor/layout.hpp>
#include <coffi/editor/coff_editor.hpp>

#include <variant>
#include <fstream>
#include <vector>

namespace coffi {

// ================================================================
//  file_buffer — owns file data, provides byte_view
// ================================================================

class file_buffer {
    std::vector<char> data_;

public:
    file_buffer() = default;
    explicit file_buffer(std::vector<char> d) : data_(std::move(d)) {}

    [[nodiscard]] byte_view view() const noexcept {
        return {data_.data(), data_.size()};
    }
    [[nodiscard]] std::size_t size() const noexcept { return data_.size(); }
    [[nodiscard]] bool empty() const noexcept { return data_.empty(); }

    [[nodiscard]] static result<file_buffer> from_file(const std::string& path) {
        std::ifstream ifs(path, std::ios::binary | std::ios::ate);
        if (!ifs) return error_code::file_too_small;
        auto sz = static_cast<std::size_t>(ifs.tellg());
        ifs.seekg(0);
        std::vector<char> buf(sz);
        ifs.read(buf.data(), static_cast<std::streamsize>(sz));
        if (!ifs) return error_code::file_too_small;
        return file_buffer{std::move(buf)};
    }
};

// ================================================================
//  coff_file<Traits> — the main parser
// ================================================================

template <typename Traits>
class coff_file {
    byte_view data_;

    // Cached offsets (computed once during from_view validation)
    std::size_t coff_hdr_off_     = 0;
    std::size_t opt_hdr_off_      = 0;
    std::size_t win_hdr_off_      = 0;
    std::size_t dirs_off_         = 0;
    std::size_t sections_off_     = 0;
    std::size_t sym_table_off_    = 0;

    uint16_t    section_count_    = 0;
    uint32_t    symbol_count_     = 0;
    uint16_t    opt_hdr_size_     = 0;
    uint32_t    num_dirs_         = 0;
    bool        has_dos_          = false;

    string_table_view  strings_;
    rva_resolver       resolver_;

    coff_file() = default;

    // ---- Internal: parse and cache header positions ----
    result<void> parse() noexcept {
        if (data_.size() < sizeof(coff_file_header))
            return error_code::file_too_small;

        std::size_t coff_off = 0;

        // --- Try DOS header ---
        if (data_.size() >= sizeof(msdos_header)) {
            auto dos = data_.read<msdos_header>(0);
            if (dos) {
                uint8_t s0 = static_cast<uint8_t>(dos->signature & 0xFF);
                uint8_t s1 = static_cast<uint8_t>(dos->signature >> 8);
                if (s0 == PEMAG0 && s1 == PEMAG1) {
                    has_dos_ = true;
                    auto pe_loc = static_cast<std::size_t>(dos->pe_sign_location);
                    auto pe_end = checked_add(pe_loc, std::size_t{4});
                    if (!pe_end || *pe_end > data_.size())
                        return error_code::truncated_header;
                    auto pe_sig = data_.read<uint32_t>(pe_loc);
                    if (!pe_sig || *pe_sig != PE_SIGNATURE)
                        return error_code::invalid_pe_signature;
                    coff_off = *pe_end;
                }
            }
        }

        coff_hdr_off_ = coff_off;
        auto coff = data_.read<coff_file_header>(coff_hdr_off_);
        if (!coff) return coff.error();

        section_count_ = coff->sections_count;
        symbol_count_  = coff->symbols_count;
        sym_table_off_ = coff->symbol_table_offset;
        opt_hdr_size_  = coff->optional_header_size;

        opt_hdr_off_ = coff_hdr_off_ + sizeof(coff_file_header);

        // --- Optional + Win header ---
        if (opt_hdr_size_ > 0) {
            auto opt = data_.read<typename Traits::optional_header_type>(opt_hdr_off_);
            if (!opt) return opt.error();
            if (opt->magic != Traits::magic) return error_code::invalid_magic;

            win_hdr_off_ = opt_hdr_off_ + sizeof(typename Traits::optional_header_type);
            auto win = data_.read<typename Traits::win_header_type>(win_hdr_off_);
            if (!win) return win.error();

            num_dirs_ = win->number_of_rva_and_sizes;
            dirs_off_ = win_hdr_off_ + sizeof(typename Traits::win_header_type);
        }

        // --- Section headers ---
        sections_off_ = opt_hdr_off_ + opt_hdr_size_;

        // --- String table (immediately after symbol table) ---
        if (sym_table_off_ > 0 && symbol_count_ > 0) {
            auto sym_bytes = checked_mul<std::size_t>(symbol_count_, sizeof(symbol_record));
            if (sym_bytes) {
                auto str_off = checked_add(static_cast<std::size_t>(sym_table_off_), *sym_bytes);
                if (str_off && *str_off + 4 <= data_.size()) {
                    auto str_sz = data_.read<uint32_t>(*str_off);
                    if (str_sz && *str_off + *str_sz <= data_.size()) {
                        auto sv = data_.subview(*str_off, *str_sz);
                        if (sv) strings_ = string_table_view{*sv};
                    }
                }
            }
        }

        // --- RVA resolver ---
        resolver_ = rva_resolver(data_, sections_off_, section_count_);

        return {};
    }

public:
    // ---- Factory ----

    /// Create from an existing byte_view (zero-copy, user owns the buffer).
    [[nodiscard]] static result<coff_file> from_view(byte_view data) noexcept {
        coff_file f;
        f.data_ = data;
        auto r = f.parse();
        if (!r) return r.error();
        return f;
    }

    // ---- Header accessors ----

    [[nodiscard]] result<msdos_header> dos_header() const noexcept {
        if (!has_dos_) return error_code::invalid_magic;
        return data_.read<msdos_header>(0);
    }

    [[nodiscard]] result<coff_file_header> coff_header() const noexcept {
        return data_.read<coff_file_header>(coff_hdr_off_);
    }

    [[nodiscard]] result<typename Traits::optional_header_type> optional_header() const noexcept {
        if (opt_hdr_size_ == 0) return error_code::truncated_header;
        return data_.read<typename Traits::optional_header_type>(opt_hdr_off_);
    }

    [[nodiscard]] result<typename Traits::win_header_type> win_header() const noexcept {
        if (win_hdr_off_ == 0) return error_code::truncated_header;
        return data_.read<typename Traits::win_header_type>(win_hdr_off_);
    }

    [[nodiscard]] result<image_data_directory> data_directory(uint32_t index) const noexcept {
        if (index >= num_dirs_) return error_code::out_of_bounds;
        return data_.read<image_data_directory>(dirs_off_ + index * sizeof(image_data_directory));
    }

    // ---- Lazy views ----

    [[nodiscard]] section_range<Traits> sections() const noexcept {
        return {data_, sections_off_, section_count_, &strings_};
    }

    [[nodiscard]] symbol_range symbols() const noexcept {
        return {data_, sym_table_off_, symbol_count_, &strings_};
    }

    [[nodiscard]] import_range<Traits> imports() const noexcept {
        auto dir = data_directory(DIR_IMPORT);
        if (!dir) return {&resolver_, 0, 0};
        return {&resolver_, dir->virtual_address, dir->size};
    }

    // ---- Raw access ----

    [[nodiscard]] byte_view             raw_data()  const noexcept { return data_; }
    [[nodiscard]] const rva_resolver&   rva()       const noexcept { return resolver_; }
    [[nodiscard]] const string_table_view& strings() const noexcept { return strings_; }
    [[nodiscard]] bool has_dos_header()             const noexcept { return has_dos_; }
    [[nodiscard]] uint16_t section_count()          const noexcept { return section_count_; }
    [[nodiscard]] uint32_t symbol_count()           const noexcept { return symbol_count_; }
};

// ================================================================
//  Architecture auto-detection
// ================================================================

[[nodiscard]] inline result<detected_arch> detect_architecture(byte_view data) noexcept {
    if (data.size() < sizeof(coff_file_header))
        return error_code::file_too_small;

    std::size_t coff_off = 0;
    bool has_dos = false;

    // Try DOS header → PE signature
    if (data.size() >= sizeof(msdos_header)) {
        auto dos = data.read<msdos_header>(0);
        if (dos) {
            auto s0 = static_cast<uint8_t>(dos->signature & 0xFF);
            auto s1 = static_cast<uint8_t>(dos->signature >> 8);
            if (s0 == PEMAG0 && s1 == PEMAG1) {
                auto pe_loc = static_cast<std::size_t>(dos->pe_sign_location);
                if (pe_loc + 4 <= data.size()) {
                    auto pe_sig = data.read<uint32_t>(pe_loc);
                    if (pe_sig && *pe_sig == PE_SIGNATURE) {
                        coff_off = pe_loc + 4;
                        has_dos = true;
                    }
                }
            }
        }
    }

    // Read as PE COFF header
    auto coff = data.read<coff_file_header>(coff_off);
    if (!coff) return coff.error();

    // Check PE optional header magic
    if (has_dos || coff->optional_header_size > 0) {
        if (coff->optional_header_size > 0) {
            auto magic = data.read<uint16_t>(coff_off + sizeof(coff_file_header));
            if (magic) {
                if (*magic == OH_MAGIC_PE32PLUS) return detected_arch::pe32plus;
                if (*magic == OH_MAGIC_PE32 || *magic == OH_MAGIC_PE32ROM)
                    return detected_arch::pe32;
            }
        }
        // Has DOS header but unknown optional magic → still PE32
        if (has_dos) return detected_arch::pe32;
    }

    // Check CEVA machine types
    if (coff->machine == CEVA_MACHINE_XC4210_LIB ||
        coff->machine == CEVA_MACHINE_XC4210_OBJ) {
        return detected_arch::ceva;
    }

    // Check known PE machine types → raw COFF object (no DOS header)
    switch (coff->machine) {
        case MACHINE_I386: case MACHINE_AMD64: case MACHINE_ARM:
        case MACHINE_ARMNT: case MACHINE_ARM64: case MACHINE_POWERPC:
            return detected_arch::pe32;  // raw COFF object
        default: break;
    }

    // Try TI format (different header layout)
    if (data.size() >= sizeof(coff_file_header_ti)) {
        auto ti = data.read<coff_file_header_ti>(0);
        if (ti) {
            switch (ti->target_id) {
                case TI_TMS470: case TI_TMS320C5400: case TI_TMS320C6000:
                case TI_TMS320C5500: case TI_TMS320C2800: case TI_MSP430:
                case TI_TMS320C5500PLUS:
                    return detected_arch::ti;
                default: break;
            }
        }
    }

    return detected_arch::unknown;
}

// ================================================================
//  Type-erased variant for auto-detection
// ================================================================

using any_coff_file = std::variant<
    coff_file<pe32_traits>,
    coff_file<pe32plus_traits>
>;

[[nodiscard]] inline result<any_coff_file> auto_load(byte_view data) noexcept {
    auto arch = detect_architecture(data);
    if (!arch) return arch.error();

    switch (*arch) {
        case detected_arch::pe32: {
            auto f = coff_file<pe32_traits>::from_view(data);
            if (!f) return f.error();
            return any_coff_file{std::move(*f)};
        }
        case detected_arch::pe32plus: {
            auto f = coff_file<pe32plus_traits>::from_view(data);
            if (!f) return f.error();
            return any_coff_file{std::move(*f)};
        }
        case detected_arch::ti:
        case detected_arch::ceva:
        case detected_arch::unknown:
            return error_code::unsupported_architecture;
    }
    return error_code::unsupported_architecture;
}

} // namespace coffi
