/*
Copyright (C) 2014-2014 by Serge Lamikhov-Center

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

/*! @file coffi_import.hpp
 * @brief COFFI library classes for PE import table manipulation.
 *
 * Do not include this file directly. This file is included by coffi.hpp.
 */

#ifndef COFFI_IMPORT_HPP
#define COFFI_IMPORT_HPP

#include <cassert>
#include <cstring>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace COFFI {

// Forward declaration — full definition is in coffi.hpp, which includes us
// after the coffi class definition.
class coffi;

//--------------------------------------------------------------------------
namespace detail {

//! RAII binary buffer builder with type-safe writes and forward-reference
//! patching. Used internally by import_section_accessor to construct
//! section data without manual offset arithmetic.
class section_data_builder
{
  public:
    section_data_builder() = default;

    //! Current write position (== buffer size so far).
    uint32_t pos() const
    {
        assert(buf_.size() <= UINT32_MAX);
        return static_cast<uint32_t>(buf_.size());
    }

    //! Write a trivially-copyable value; returns the offset where it was
    //! written.
    template <typename T>
    uint32_t write(const T& val)
    {
        static_assert(std::is_trivially_copyable_v<T>,
                      "write() requires a trivially copyable type");
        uint32_t offset = pos();
        const char* p   = reinterpret_cast<const char*>(&val);
        buf_.insert(buf_.end(), p, p + sizeof(T));
        return offset;
    }

    //! Write raw bytes; returns the offset.
    uint32_t write_bytes(const char* data, uint32_t len)
    {
        uint32_t offset = pos();
        buf_.insert(buf_.end(), data, data + len);
        return offset;
    }

    //! Write a null-terminated string; returns the offset.
    uint32_t write_str(std::string_view s)
    {
        uint32_t offset = pos();
        buf_.insert(buf_.end(), s.data(), s.data() + s.size());
        buf_.push_back('\0');
        return offset;
    }

    //! Reserve sizeof(T) zero-filled bytes; returns the offset for later
    //! patching via patch().
    template <typename T>
    uint32_t reserve()
    {
        static_assert(std::is_trivially_copyable_v<T>,
                      "reserve() requires a trivially copyable type");
        uint32_t offset = pos();
        buf_.resize(buf_.size() + sizeof(T), '\0');
        return offset;
    }

    //! Overwrite a previously written/reserved value at @p offset.
    template <typename T>
    void patch(uint32_t offset, const T& val)
    {
        static_assert(std::is_trivially_copyable_v<T>,
                      "patch() requires a trivially copyable type");
        assert(static_cast<size_t>(offset) + sizeof(T) <= buf_.size());
        std::memcpy(buf_.data() + offset, &val, sizeof(T));
    }

    //! Pad to @p boundary alignment with zero bytes; returns new pos().
    uint32_t align(uint32_t boundary)
    {
        uint32_t rem = pos() % boundary;
        if (rem != 0) {
            buf_.resize(buf_.size() + (boundary - rem), '\0');
        }
        return pos();
    }

    const char* data() const { return buf_.data(); }
    uint32_t    size() const
    {
        assert(buf_.size() <= UINT32_MAX);
        return static_cast<uint32_t>(buf_.size());
    }

  private:
    std::vector<char> buf_;
};

} // namespace detail

//--------------------------------------------------------------------------
//! Parsed representation of a single imported symbol.
struct imported_symbol
{
    std::string name;
    uint16_t    hint{0};
    bool        is_ordinal{false};
    uint32_t    ordinal{0};
};

//! Parsed representation of an imported DLL module.
struct imported_module
{
    std::string                  dll_name;
    std::vector<imported_symbol> symbols;
};

//--------------------------------------------------------------------------
//! Accessor for reading and manipulating the PE Import Directory Table.
//!
//! Construct from a mutable coffi instance.  The read side lazily parses
//! the existing import directory on first access.  The write side builds
//! a new .idata section with the correct IDT / ILT / IAT / string layout.
class import_section_accessor
{
  public:
    //----------------------------------------------------------------------
    explicit import_section_accessor(coffi& pe) : pe_(pe) {}

    // ---- Read API -------------------------------------------------------

    //! Number of imported DLLs (excluding the null terminator).
    uint32_t get_import_count() const
    {
        ensure_parsed();
        return static_cast<uint32_t>(imports_.size());
    }

    //! DLL name at index @p i.  Returns empty string if out of range.
    std::string get_dll_name(uint32_t i) const
    {
        ensure_parsed();
        if (i >= imports_.size())
            return {};
        return imports_[i].dll_name;
    }

    //! Number of symbols imported from DLL at index @p i.
    uint32_t get_symbol_count(uint32_t i) const
    {
        ensure_parsed();
        if (i >= imports_.size())
            return 0;
        return static_cast<uint32_t>(imports_[i].symbols.size());
    }

    //! Get symbol info at (dll_index, sym_index).
    //! @return false if indices are out of range.
    bool get_symbol(uint32_t dll_index, uint32_t sym_index,
                    std::string& name, uint16_t& hint) const
    {
        ensure_parsed();
        if (dll_index >= imports_.size())
            return false;
        const auto& syms = imports_[dll_index].symbols;
        if (sym_index >= syms.size())
            return false;
        name = syms[sym_index].name;
        hint = syms[sym_index].hint;
        return true;
    }

    //! All imports as a structured vector.
    const std::vector<imported_module>& get_imports() const
    {
        ensure_parsed();
        return imports_;
    }

    // ---- Write API ------------------------------------------------------

    //! Convenience: add one DLL with one symbol.
    bool add_import(const std::string& dll_name,
                    const std::string& symbol_name,
                    uint16_t           hint = 0)
    {
        return add_import(
            dll_name,
            std::vector<std::pair<std::string, uint16_t>>{{symbol_name, hint}});
    }

    //! Add a new import entry: one DLL with one or more symbols imported
    //! by name.
    //!
    //! Creates a new .idata section containing:
    //!   - Copies of all existing IDT entries (original ILT/IAT stay in
    //!     place)
    //!   - The new IDT entry + null terminator
    //!   - ILT, IAT, IMAGE_IMPORT_BY_NAME structs, DLL name string
    //!
    //! Updates DATA_DIRECTORY[1] (import table) and DATA_DIRECTORY[12]
    //! (IAT).
    //!
    //! @note Each call creates a new .idata section.  For best results,
    //!       use the multi-symbol overload to add all symbols for a DLL in
    //!       one call.  Calling add_import() multiple times for different
    //!       DLLs works correctly — each call copies existing IDT entries
    //!       into the new section — but the old .idata sections become
    //!       orphaned (their data is still referenced by IDT entries for
    //!       existing imports).
    //!
    //! @note DATA_DIRECTORY[12] (IAT) is set to cover only the newly-added
    //!       DLL's IAT.  The Windows loader finds per-DLL IATs via the IDT
    //!       entries, so this is functionally correct, but PE analysis tools
    //!       may report an incomplete IAT directory.
    //!
    //! @return true on success.
    bool add_import(
        const std::string&                                  dll_name,
        const std::vector<std::pair<std::string, uint16_t>>& symbols);

  private:
    //----------------------------------------------------------------------
    void ensure_parsed() const
    {
        if (!parsed_) {
            parse();
        }
    }

    //! Parse existing import directory from the loaded PE.
    bool parse() const;

    //! Find the section whose VA range contains @p rva.
    section* find_section_by_rva(uint32_t rva) const;

    //! Bounds-checked RVA-to-pointer resolution (single byte).
    //! @return pointer into section data, or nullptr on failure.
    const char* rva_to_ptr(uint32_t rva) const;

    //! Bounds-checked RVA-to-pointer for @p n contiguous bytes.
    //! Guarantees all @p n bytes are within the SAME section's data.
    //! @return pointer into section data, or nullptr on failure.
    const char* rva_to_ptr_n(uint32_t rva, uint32_t n) const;

    //! Read a null-terminated string from section data at @p rva, bounded
    //! by the containing section's data size.
    //! @return the string, or empty string on failure.
    std::string read_string_at_rva(uint32_t rva) const;

    //! Collect raw IMAGE_IMPORT_DESCRIPTOR entries from the current IDT.
    std::vector<image_import_descriptor> collect_existing_idt() const;

    //! Compute the next available section VA, aligned to section_alignment.
    uint32_t compute_next_section_rva() const;

    //! Build thunks (ILT + IAT) for one DLL's symbols.
    //! Template on ThunkType (uint32_t for PE32, uint64_t for PE32+).
    template <typename ThunkType>
    void build_thunks(
        detail::section_data_builder&                        builder,
        uint32_t                                             section_rva,
        const std::vector<std::pair<std::string, uint16_t>>& symbols,
        uint32_t& ilt_offset, uint32_t& iat_offset,
        std::vector<uint32_t>& ibn_offsets) const;

    coffi&                               pe_;
    mutable bool                         parsed_{false};
    mutable std::vector<imported_module>  imports_;
};

//==========================================================================
// Inline / template implementations
// (header-only library — everything must be in the header)
//==========================================================================

//--------------------------------------------------------------------------
inline section*
import_section_accessor::find_section_by_rva(uint32_t rva) const
{
    auto& sections = pe_.get_sections();
    for (auto it = sections.begin(); it != sections.end(); ++it) {
        section& sec      = *it;
        uint32_t sec_va   = sec.get_virtual_address();
        uint32_t sec_size = sec.get_virtual_size();
        if (sec_size == 0)
            sec_size = sec.get_data_size();
        // Use subtraction to avoid uint32_t overflow:
        // rva >= sec_va && rva < sec_va + sec_size
        //   ≡ (rva - sec_va) < sec_size  [when rva >= sec_va]
        if (rva >= sec_va && (rva - sec_va) < sec_size) {
            return &sec;
        }
    }
    return nullptr;
}

//--------------------------------------------------------------------------
inline const char*
import_section_accessor::rva_to_ptr(uint32_t rva) const
{
    section* sec = find_section_by_rva(rva);
    if (!sec || !sec->get_data())
        return nullptr;
    uint32_t offset = rva - sec->get_virtual_address();
    if (offset >= sec->get_data_size())
        return nullptr;
    return sec->get_data() + offset;
}

//--------------------------------------------------------------------------
inline const char*
import_section_accessor::rva_to_ptr_n(uint32_t rva, uint32_t n) const
{
    if (n == 0)
        return rva_to_ptr(rva);
    section* sec = find_section_by_rva(rva);
    if (!sec || !sec->get_data())
        return nullptr;
    uint32_t offset    = rva - sec->get_virtual_address();
    uint32_t data_size = sec->get_data_size();
    // Ensure all n bytes fit: offset + n <= data_size
    if (offset > data_size - n) // equivalent to offset + n > data_size, overflow-safe
        return nullptr;
    return sec->get_data() + offset;
}

//--------------------------------------------------------------------------
inline std::string
import_section_accessor::read_string_at_rva(uint32_t rva) const
{
    section* sec = find_section_by_rva(rva);
    if (!sec || !sec->get_data())
        return {};
    uint32_t offset    = rva - sec->get_virtual_address();
    uint32_t data_size = sec->get_data_size();
    if (offset >= data_size)
        return {};
    const char* start     = sec->get_data() + offset;
    uint32_t    remaining = data_size - offset;
    // Find null terminator within bounds
    auto len = static_cast<size_t>(
        strnlen(start, static_cast<size_t>(remaining)));
    return {start, len};
}

//--------------------------------------------------------------------------
inline bool
import_section_accessor::parse() const
{
    imports_.clear();

    const auto& dirs = pe_.get_directories();
    if (dirs.get_count() <= DIRECTORY_IMPORT_TABLE) {
        parsed_ = true;
        return true; // no import directory — not an error
    }

    const directory* import_dir = dirs[DIRECTORY_IMPORT_TABLE];
    if (!import_dir) {
        parsed_ = true;
        return true;
    }
    uint32_t idt_rva  = import_dir->get_virtual_address();
    uint32_t idt_size = import_dir->get_size();
    if (idt_rva == 0 || idt_size == 0) {
        parsed_ = true;
        return true; // no imports
    }

    // Bound iteration by declared directory size
    uint32_t max_entries = idt_size / sizeof(image_import_descriptor);

    // Determine thunk width
    bool is_plus = pe_.get_optional_header() &&
                   pe_.get_optional_header()->get_magic() == OH_MAGIC_PE32PLUS;

    // Walk IMAGE_IMPORT_DESCRIPTORs
    for (uint32_t idx = 0; idx < max_entries; ++idx) {
        // Overflow-safe RVA computation
        uint64_t entry_rva64 =
            static_cast<uint64_t>(idt_rva) +
            static_cast<uint64_t>(idx) * sizeof(image_import_descriptor);
        if (entry_rva64 > UINT32_MAX)
            break;
        auto entry_rva = static_cast<uint32_t>(entry_rva64);

        // Ensure all 20 bytes are contiguous within one section
        const char* entry_ptr = rva_to_ptr_n(entry_rva, sizeof(image_import_descriptor));
        if (!entry_ptr)
            break;

        image_import_descriptor desc;
        std::memcpy(&desc, entry_ptr, sizeof(desc));

        // Null terminator check
        if (desc.original_first_thunk == 0 && desc.first_thunk == 0 &&
            desc.name == 0)
            break;

        // Resolve DLL name with bounded read
        imported_module mod;
        mod.dll_name = read_string_at_rva(desc.name);
        if (mod.dll_name.empty())
            continue; // skip corrupt entry

        // Walk ILT (prefer OriginalFirstThunk; fall back to FirstThunk)
        uint32_t thunk_rva =
            (desc.original_first_thunk != 0) ? desc.original_first_thunk
                                             : desc.first_thunk;

        if (is_plus) {
            for (uint32_t t = thunk_rva;; t += 8) {
                const char* tp = rva_to_ptr_n(t, 8);
                if (!tp)
                    break;
                uint64_t thunk_val;
                std::memcpy(&thunk_val, tp, 8);
                if (thunk_val == 0)
                    break;

                imported_symbol sym;
                if (thunk_val & (uint64_t{1} << 63)) {
                    sym.is_ordinal = true;
                    sym.ordinal = static_cast<uint32_t>(thunk_val & 0xFFFF);
                }
                else {
                    auto ibn_rva = static_cast<uint32_t>(thunk_val);
                    const char* ibn_ptr = rva_to_ptr_n(ibn_rva, sizeof(image_import_by_name));
                    if (!ibn_ptr)
                        continue;
                    image_import_by_name ibn;
                    std::memcpy(&ibn, ibn_ptr, sizeof(ibn));
                    sym.hint = ibn.hint;
                    // Overflow-safe name RVA
                    uint32_t name_rva = ibn_rva + sizeof(image_import_by_name);
                    if (name_rva >= ibn_rva) // no overflow
                        sym.name = read_string_at_rva(name_rva);
                }
                mod.symbols.push_back(std::move(sym));

                if (t > UINT32_MAX - 8)
                    break;
            }
        }
        else {
            // PE32: 4-byte thunks
            for (uint32_t t = thunk_rva;; t += 4) {
                const char* tp = rva_to_ptr_n(t, 4);
                if (!tp)
                    break;
                uint32_t thunk_val;
                std::memcpy(&thunk_val, tp, 4);
                if (thunk_val == 0)
                    break;

                imported_symbol sym;
                if (thunk_val & (uint32_t{1} << 31)) {
                    sym.is_ordinal = true;
                    sym.ordinal = thunk_val & 0xFFFF;
                }
                else {
                    const char* ibn_ptr = rva_to_ptr_n(thunk_val, sizeof(image_import_by_name));
                    if (!ibn_ptr)
                        continue;
                    image_import_by_name ibn;
                    std::memcpy(&ibn, ibn_ptr, sizeof(ibn));
                    sym.hint = ibn.hint;
                    uint32_t name_rva = thunk_val + sizeof(image_import_by_name);
                    if (name_rva >= thunk_val) // no overflow
                        sym.name = read_string_at_rva(name_rva);
                }
                mod.symbols.push_back(std::move(sym));

                if (t > UINT32_MAX - 4)
                    break;
            }
        }

        imports_.push_back(std::move(mod));
    }

    parsed_ = true; // set AFTER successful parse
    return true;
}

//--------------------------------------------------------------------------
inline std::vector<image_import_descriptor>
import_section_accessor::collect_existing_idt() const
{
    std::vector<image_import_descriptor> entries;

    const auto& dirs = pe_.get_directories();
    if (dirs.get_count() <= DIRECTORY_IMPORT_TABLE)
        return entries;

    const directory* import_dir = dirs[DIRECTORY_IMPORT_TABLE];
    if (!import_dir)
        return entries;
    uint32_t idt_rva  = import_dir->get_virtual_address();
    uint32_t idt_size = import_dir->get_size();
    if (idt_rva == 0 || idt_size == 0)
        return entries;

    uint32_t max_entries = idt_size / sizeof(image_import_descriptor);

    for (uint32_t idx = 0; idx < max_entries; ++idx) {
        uint64_t rva64 =
            static_cast<uint64_t>(idt_rva) +
            static_cast<uint64_t>(idx) * sizeof(image_import_descriptor);
        if (rva64 > UINT32_MAX)
            break;
        auto rva = static_cast<uint32_t>(rva64);

        const char* ptr = rva_to_ptr_n(rva, sizeof(image_import_descriptor));
        if (!ptr)
            break;

        image_import_descriptor desc;
        std::memcpy(&desc, ptr, sizeof(desc));

        if (desc.original_first_thunk == 0 && desc.first_thunk == 0 &&
            desc.name == 0)
            break;

        entries.push_back(desc);
    }

    return entries;
}

//--------------------------------------------------------------------------
inline uint32_t
import_section_accessor::compute_next_section_rva() const
{
    uint32_t section_alignment = 0x1000; // default
    const win_header* wh = pe_.get_win_header();
    if (wh)
        section_alignment = wh->get_section_alignment();
    // Validate power-of-two (required by PE spec)
    if (section_alignment == 0 ||
        (section_alignment & (section_alignment - 1)) != 0)
        section_alignment = 0x1000;

    uint64_t max_end = 0;
    for (auto it = pe_.get_sections().begin();
         it != pe_.get_sections().end(); ++it) {
        const section& sec = *it;
        uint32_t vs = sec.get_virtual_size();
        if (vs == 0)
            vs = sec.get_data_size();
        // Use uint64_t to avoid overflow
        uint64_t end = static_cast<uint64_t>(sec.get_virtual_address()) + vs;
        // Align up
        end = (end + section_alignment - 1) & ~(static_cast<uint64_t>(section_alignment) - 1);
        if (end > max_end)
            max_end = end;
    }

    // If no sections yet, start after typical header area
    if (max_end == 0)
        max_end = section_alignment;

    // Clamp to 32-bit address space
    if (max_end > UINT32_MAX)
        max_end = UINT32_MAX & ~(static_cast<uint64_t>(section_alignment) - 1);

    return static_cast<uint32_t>(max_end);
}

//--------------------------------------------------------------------------
template <typename ThunkType>
inline void
import_section_accessor::build_thunks(
    detail::section_data_builder&                        builder,
    uint32_t                                             section_rva,
    const std::vector<std::pair<std::string, uint16_t>>& symbols,
    uint32_t& ilt_offset, uint32_t& iat_offset,
    std::vector<uint32_t>& ibn_offsets) const
{
    // ---- ILT (Import Lookup Table) ----
    ilt_offset = builder.pos();
    // Reserve one thunk per symbol + null terminator
    std::vector<uint32_t> ilt_entry_offsets;
    for (size_t i = 0; i < symbols.size(); ++i) {
        ilt_entry_offsets.push_back(builder.reserve<ThunkType>());
    }
    builder.write(ThunkType{0}); // null terminator

    // ---- IAT (Import Address Table) — same structure as ILT ----
    iat_offset = builder.pos();
    std::vector<uint32_t> iat_entry_offsets;
    for (size_t i = 0; i < symbols.size(); ++i) {
        iat_entry_offsets.push_back(builder.reserve<ThunkType>());
    }
    builder.write(ThunkType{0}); // null terminator

    // ---- IMAGE_IMPORT_BY_NAME entries ----
    ibn_offsets.clear();
    for (size_t i = 0; i < symbols.size(); ++i) {
        builder.align(2); // PE spec: hint/name entries are word-aligned
        uint32_t ibn_off = builder.pos();
        ibn_offsets.push_back(ibn_off);

        image_import_by_name ibn{symbols[i].second};
        builder.write(ibn);
        builder.write_str(symbols[i].first); // null-terminated name
    }

    // ---- Patch ILT and IAT entries to point to their IBN ----
    for (size_t i = 0; i < symbols.size(); ++i) {
        // Overflow-safe RVA computation
        auto ibn_rva = static_cast<ThunkType>(
            static_cast<uint64_t>(section_rva) + ibn_offsets[i]);
        builder.patch<ThunkType>(ilt_entry_offsets[i], ibn_rva);
        builder.patch<ThunkType>(iat_entry_offsets[i], ibn_rva);
    }
}

//--------------------------------------------------------------------------
inline bool
import_section_accessor::add_import(
    const std::string&                                  dll_name,
    const std::vector<std::pair<std::string, uint16_t>>& symbols)
{
    if (dll_name.empty() || symbols.empty())
        return false;

    // Require an optional header — without one this is not a PE image
    if (!pe_.get_optional_header())
        return false;

    // Ensure we have parsed existing imports
    ensure_parsed();

    // PE32 vs PE32+
    bool is_plus =
        pe_.get_optional_header()->get_magic() == OH_MAGIC_PE32PLUS;

    // Collect existing raw IDT entries (their ILT/IAT RVAs stay valid)
    auto existing_idt = collect_existing_idt();

    // Compute where the new section will live
    uint32_t section_rva = compute_next_section_rva();

    // ---- Build section data ----
    detail::section_data_builder builder;

    // Phase 1a: Copy existing IDT entries
    for (const auto& entry : existing_idt) {
        builder.write(entry);
    }

    // Phase 1b: Reserve space for our new IDT entry (forward ref)
    uint32_t new_idt_offset = builder.reserve<image_import_descriptor>();

    // Phase 1c: Write IDT null terminator
    image_import_descriptor null_desc{};
    builder.write(null_desc);

    // Phase 1d: Build ILT + IAT + IBN entries via template dispatch
    uint32_t              ilt_offset = 0;
    uint32_t              iat_offset = 0;
    std::vector<uint32_t> ibn_offsets;

    if (is_plus) {
        build_thunks<uint64_t>(builder, section_rva, symbols,
                               ilt_offset, iat_offset, ibn_offsets);
    }
    else {
        build_thunks<uint32_t>(builder, section_rva, symbols,
                               ilt_offset, iat_offset, ibn_offsets);
    }

    // Phase 1e: Write DLL name string
    builder.align(2);
    uint32_t dll_name_offset = builder.write_str(dll_name);

    // Phase 2: Patch the new IDT entry with resolved RVAs.
    // Use uint64_t to detect overflow.
    auto safe_rva = [section_rva](uint32_t offset) -> uint32_t {
        uint64_t rva = static_cast<uint64_t>(section_rva) + offset;
        return (rva <= UINT32_MAX) ? static_cast<uint32_t>(rva) : 0;
    };

    image_import_descriptor new_desc{};
    new_desc.original_first_thunk = safe_rva(ilt_offset);
    new_desc.time_date_stamp      = 0;
    new_desc.forwarder_chain      = 0;
    new_desc.name                 = safe_rva(dll_name_offset);
    new_desc.first_thunk          = safe_rva(iat_offset);
    builder.patch(new_idt_offset, new_desc);

    // ---- Create the section ----
    section* new_sec = pe_.add_section(".idata");
    new_sec->set_data(builder.data(), builder.size());
    new_sec->set_virtual_address(section_rva);
    new_sec->set_virtual_size(builder.size());
    new_sec->set_flags(IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE |
                       IMAGE_SCN_CNT_INITIALIZED_DATA);

    // ---- Update data directories ----
    auto& dirs = pe_.get_directories();

    // Ensure enough directories exist (need at least 13: indices 0..12)
    while (dirs.get_count() <= DIRECTORY_IAT) {
        pe_.add_directory(image_data_directory{0, 0});
    }

    // DATA_DIRECTORY[1] — Import Table
    uint32_t idt_total_size =
        static_cast<uint32_t>((existing_idt.size() + 1 + 1) *
                              sizeof(image_import_descriptor));
    dirs[DIRECTORY_IMPORT_TABLE]->set_virtual_address(section_rva);
    dirs[DIRECTORY_IMPORT_TABLE]->set_size(idt_total_size);

    // DATA_DIRECTORY[12] — IAT (covers this DLL's IAT; see class docs)
    uint32_t thunk_size  = is_plus ? 8u : 4u;
    uint32_t iat_entries = static_cast<uint32_t>(symbols.size()) + 1; // +terminator
    dirs[DIRECTORY_IAT]->set_virtual_address(safe_rva(iat_offset));
    dirs[DIRECTORY_IAT]->set_size(iat_entries * thunk_size);

    // Invalidate parse cache
    parsed_ = false;
    imports_.clear();

    return true;
}

} // namespace COFFI

#endif // COFFI_IMPORT_HPP
