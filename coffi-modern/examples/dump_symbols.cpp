/// dump_symbols — List all symbols in a COFF/PE file.
///
/// Usage: dump_symbols <file.exe|file.obj>
///
/// Demonstrates: symbol_range iteration, lazy pipe filtering, string table resolution.

#include <coffi/coffi.hpp>
#include <iostream>
#include <iomanip>

using namespace coffi;

template <typename Traits>
void dump(const coff_file<Traits>& file) {
    auto syms = file.symbols();
    if (syms.empty()) {
        std::cout << "(no symbols)\n";
        return;
    }

    std::cout << std::left
              << std::setw(8)  << "Index"
              << std::setw(40) << "Name"
              << std::setw(12) << "Value"
              << std::setw(8)  << "Sect"
              << std::setw(8)  << "Class"
              << std::setw(6)  << "Aux"
              << "\n"
              << std::string(82, '-') << "\n";

    uint32_t idx = 0;
    for (auto sym : syms) {
        auto name = sym.name();
        std::cout << std::left
                  << std::setw(8)  << idx
                  << std::setw(40) << (name.empty() ? "(unnamed)" : name)
                  << "0x" << std::hex << std::setw(10) << sym.value() << std::dec
                  << std::setw(8)  << sym.section_number()
                  << std::setw(8)  << static_cast<int>(sym.storage_class())
                  << std::setw(6)  << static_cast<int>(sym.aux_count())
                  << "\n";
        idx += 1 + sym.aux_count();
    }

    std::cout << "\nTotal: " << syms.count() << " records ("
              << idx << " including aux)\n";

    // Demo: pipe filter — find symbols in section 1
    std::cout << "\n--- Symbols in section 1 (pipe filter) ---\n";
    auto sec1_syms = file.symbols()
        | filter([](auto s) { return s.section_number() == 1; });

    for (auto sym : sec1_syms) {
        std::cout << "  " << sym.name() << " = 0x"
                  << std::hex << sym.value() << std::dec << "\n";
    }
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
