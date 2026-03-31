/// pe_info — Print basic PE file information: headers, sections, and flags.
///
/// Usage: pe_info <file.exe>

#include <coffi/coffi.hpp>
#include <iostream>
#include <iomanip>
#include <cstdlib>

using namespace coffi;

template <typename Traits>
void dump(const coff_file<Traits>& file) {
    // --- COFF Header ---
    auto hdr = file.coff_header();
    if (!hdr) { std::cerr << "Failed to read COFF header\n"; return; }

    std::cout << "COFF Header\n"
              << "  Machine:          0x" << std::hex << hdr->machine << std::dec << "\n"
              << "  Sections:         " << hdr->sections_count << "\n"
              << "  Symbols:          " << hdr->symbols_count << "\n"
              << "  Timestamp:        " << hdr->time_date_stamp << "\n"
              << "  Opt Header Size:  " << hdr->optional_header_size << "\n\n";

    // --- Optional Header ---
    auto opt = file.optional_header();
    if (opt) {
        std::cout << "Optional Header\n"
                  << "  Magic:            0x" << std::hex << opt->magic << std::dec << "\n"
                  << "  Entry Point:      0x" << std::hex << opt->entry_point_address << std::dec << "\n"
                  << "  Code Base:        0x" << std::hex << opt->code_base << std::dec << "\n\n";
    }

    // --- Win Header ---
    auto win = file.win_header();
    if (win) {
        std::cout << "Windows NT Header\n"
                  << "  Image Base:       0x" << std::hex << win->image_base << std::dec << "\n"
                  << "  Section Align:    0x" << std::hex << win->section_alignment << std::dec << "\n"
                  << "  File Align:       0x" << std::hex << win->file_alignment << std::dec << "\n"
                  << "  Image Size:       0x" << std::hex << win->image_size << std::dec << "\n\n";
    }

    // --- Sections ---
    std::cout << "Sections (" << file.section_count() << ")\n"
              << std::left
              << std::setw(10) << "  Name"
              << std::setw(12) << "VirtAddr"
              << std::setw(12) << "VirtSize"
              << std::setw(12) << "RawSize"
              << std::setw(12) << "RawOff"
              << "Flags\n"
              << "  " << std::string(68, '-') << "\n";

    for (auto sec : file.sections()) {
        std::cout << "  " << std::left << std::setw(10) << sec.name()
                  << std::hex
                  << std::setw(12) << sec.virtual_address()
                  << std::setw(12) << sec.virtual_size()
                  << std::setw(12) << sec.data_size()
                  << std::setw(12) << sec.data_offset()
                  << std::dec;

        if (sec.is_code())       std::cout << "CODE ";
        if (sec.is_data())       std::cout << "DATA ";
        if (sec.is_bss())        std::cout << "BSS ";
        if (sec.is_readable())   std::cout << "R";
        if (sec.is_writable())   std::cout << "W";
        if (sec.is_executable()) std::cout << "X";
        std::cout << "\n";
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

    auto arch = detect_architecture(buf->view());
    if (!arch) {
        std::cerr << "Error: " << to_string(arch.error()) << "\n";
        return 1;
    }

    switch (*arch) {
        case detected_arch::pe32: {
            auto f = coff_file<pe32_traits>::from_view(buf->view());
            if (!f) { std::cerr << "Error: " << to_string(f.error()) << "\n"; return 1; }
            std::cout << "=== PE32 (32-bit) ===\n\n";
            dump(*f);
            break;
        }
        case detected_arch::pe32plus: {
            auto f = coff_file<pe32plus_traits>::from_view(buf->view());
            if (!f) { std::cerr << "Error: " << to_string(f.error()) << "\n"; return 1; }
            std::cout << "=== PE32+ (64-bit) ===\n\n";
            dump(*f);
            break;
        }
        default:
            std::cerr << "Error: unsupported architecture\n";
            return 1;
    }
}
