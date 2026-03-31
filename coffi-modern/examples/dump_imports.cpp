/// dump_imports — List all PE import table entries (DLLs and functions).
///
/// Usage: dump_imports <file.exe>
///
/// Demonstrates: import_range, import_module_ref, import_symbol_ref,
///               PE32 vs PE32+ transparent handling via std::visit.

#include <coffi/coffi.hpp>
#include <iostream>
#include <iomanip>

using namespace coffi;

template <typename Traits>
void dump(const coff_file<Traits>& file) {
    auto imps = file.imports();
    if (imps.empty()) {
        std::cout << "(no imports)\n";
        return;
    }

    uint32_t dll_idx = 0;
    for (auto mod : imps) {
        std::cout << "[" << dll_idx << "] " << mod.dll_name() << "\n";

        uint32_t sym_idx = 0;
        for (auto sym : mod.symbols()) {
            if (sym.is_ordinal()) {
                std::cout << "    " << std::setw(4) << sym_idx
                          << "  ordinal " << sym.ordinal() << "\n";
            } else {
                std::cout << "    " << std::setw(4) << sym_idx
                          << "  hint=" << std::setw(4) << sym.hint()
                          << "  " << sym.name() << "\n";
            }
            ++sym_idx;
        }
        ++dll_idx;
    }

    std::cout << "\nTotal: " << dll_idx << " DLL(s)\n";
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <pe-file>\n";
        return 1;
    }

    auto buf = file_buffer::from_file(argv[1]);
    if (!buf) {
        std::cerr << "Error: cannot open '" << argv[1] << "'\n";
        return 1;
    }

    auto file = auto_load(buf->view());
    if (!file) {
        std::cerr << "Error: " << to_string(file.error()) << "\n";
        return 1;
    }

    std::visit([](auto& f) { dump(f); }, *file);
}
