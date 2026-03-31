#pragma once

/// Lazy import table builder for PE files.
/// Accumulates import descriptions and materializes them into an .idata
/// section during save(), matching the original COFFI's import construction.

#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include <coffi/core/error.hpp>
#include <coffi/core/result.hpp>
#include <coffi/editor/data_builder.hpp>
#include <coffi/platform/schema.hpp>

namespace coffi {

struct import_symbol_desc {
    std::string name;
    uint16_t    hint       = 0;
    bool        is_ordinal = false;
    uint32_t    ordinal    = 0;
};

struct import_module_desc {
    std::string                      dll_name;
    std::vector<import_symbol_desc>  symbols;
};

struct import_build_result {
    std::vector<char>      section_data;
    image_data_directory   import_dir;   // DIR_IMPORT
    image_data_directory   iat_dir;      // DIR_IAT
};

template <typename Traits>
class import_builder {
    std::vector<import_module_desc> modules_;

public:
    import_builder() = default;

    void add_module(std::string dll_name, std::vector<import_symbol_desc> symbols) {
        modules_.push_back({std::move(dll_name), std::move(symbols)});
    }

    void add_symbol(std::string_view dll_name, std::string_view symbol_name,
                    uint16_t hint = 0) {
        for (auto& m : modules_) {
            if (m.dll_name == dll_name) {
                m.symbols.push_back({std::string(symbol_name), hint, false, 0});
                return;
            }
        }
        import_module_desc mod;
        mod.dll_name = std::string(dll_name);
        mod.symbols.push_back({std::string(symbol_name), hint, false, 0});
        modules_.push_back(std::move(mod));
    }

    [[nodiscard]] std::size_t module_count() const noexcept { return modules_.size(); }
    [[nodiscard]] bool        empty()        const noexcept { return modules_.empty(); }
    void clear() noexcept { modules_.clear(); }

    [[nodiscard]] result<import_build_result> build(uint32_t section_rva) const noexcept {
        using thunk_t = typename Traits::address_type;
        constexpr auto thunk_sz = static_cast<uint32_t>(sizeof(thunk_t));

        data_builder db;

        // Phase 1: IDT entries (one per module + null terminator)
        std::vector<uint32_t> idt_offsets;
        for (std::size_t i = 0; i < modules_.size(); ++i) {
            auto off = db.reserve<image_import_descriptor>();
            if (!off) return off.error();
            idt_offsets.push_back(*off);
        }
        // Null terminator
        {
            image_import_descriptor null_desc{};
            (void)db.write(null_desc);
        }
        uint32_t idt_total = static_cast<uint32_t>(
            (modules_.size() + 1) * sizeof(image_import_descriptor));

        // Phase 2: Per-module ILT, IAT, hint/name, DLL name
        uint32_t first_iat_offset = 0;
        uint32_t total_iat_size = 0;

        for (std::size_t mi = 0; mi < modules_.size(); ++mi) {
            auto& mod = modules_[mi];
            auto sym_count = static_cast<uint32_t>(mod.symbols.size());

            // ILT
            auto ilt_off = db.pos();
            std::vector<uint32_t> ilt_thunk_offsets;
            for (uint32_t si = 0; si < sym_count; ++si) {
                auto off = db.reserve_bytes(thunk_sz);
                if (!off) return off.error();
                ilt_thunk_offsets.push_back(*off);
            }
            (void)db.reserve_bytes(thunk_sz); // ILT null terminator

            // IAT (same structure)
            auto iat_off = db.pos();
            if (mi == 0) first_iat_offset = iat_off;
            std::vector<uint32_t> iat_thunk_offsets;
            for (uint32_t si = 0; si < sym_count; ++si) {
                auto off = db.reserve_bytes(thunk_sz);
                if (!off) return off.error();
                iat_thunk_offsets.push_back(*off);
            }
            (void)db.reserve_bytes(thunk_sz); // IAT null terminator
            total_iat_size += (sym_count + 1) * thunk_sz;

            // Hint/Name entries
            for (uint32_t si = 0; si < sym_count; ++si) {
                auto& sym = mod.symbols[si];
                thunk_t thunk_val;

                if (sym.is_ordinal) {
                    thunk_val = static_cast<thunk_t>(Traits::ordinal_flag | sym.ordinal);
                } else {
                    (void)db.align(2);
                    auto ibn_off = db.pos();
                    (void)db.write(sym.hint);
                    (void)db.write_str(sym.name);
                    thunk_val = static_cast<thunk_t>(section_rva + ibn_off);
                }
                (void)db.patch(ilt_thunk_offsets[si], thunk_val);
                (void)db.patch(iat_thunk_offsets[si], thunk_val);
            }

            // DLL name
            (void)db.align(2);
            auto dll_name_off = db.pos();
            (void)db.write_str(mod.dll_name);

            // Patch IDT entry
            image_import_descriptor idt{};
            idt.original_first_thunk = section_rva + ilt_off;
            idt.name                 = section_rva + dll_name_off;
            idt.first_thunk          = section_rva + iat_off;
            (void)db.patch(idt_offsets[mi], idt);
        }

        import_build_result res;
        res.section_data = db.take();
        res.import_dir   = {section_rva, idt_total};
        res.iat_dir      = {section_rva + first_iat_offset, total_iat_size};
        return res;
    }
};

} // namespace coffi
