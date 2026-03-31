#include <gtest/gtest.h>
#include <coffi/coffi.hpp>
#include <cstring>
#include <vector>

using namespace coffi;

// ================================================================
//  Helper: build a minimal PE32 file in memory
// ================================================================

static std::vector<char> build_minimal_pe32() {
    // Layout:
    //   0   : DOS header          (64 bytes)
    //   64  : PE signature        (4 bytes)
    //   68  : COFF header         (20 bytes)
    //   88  : Optional header PE  (28 bytes)
    //   116 : Win header PE       (68 bytes)
    //   184 : Data directories    (16 * 8 = 128 bytes)
    //   312 : Section header 0    (40 bytes)
    //   352 : Section 0 data      (16 bytes)
    //   Total: 368 bytes

    constexpr std::size_t FILE_SIZE = 512;  // round up
    std::vector<char> buf(FILE_SIZE, 0);

    // --- DOS header ---
    msdos_header dos{};
    dos.signature = static_cast<uint16_t>(PEMAG0) | (static_cast<uint16_t>(PEMAG1) << 8);
    dos.pe_sign_location = 64;
    std::memcpy(buf.data(), &dos, sizeof(dos));

    // --- PE signature ---
    uint32_t pe_sig = PE_SIGNATURE;
    std::memcpy(buf.data() + 64, &pe_sig, 4);

    // --- COFF header ---
    coff_file_header coff{};
    coff.machine = MACHINE_I386;
    coff.sections_count = 1;
    coff.optional_header_size = static_cast<uint16_t>(
        sizeof(coff_optional_header_pe) + sizeof(win_header_pe) +
        16 * sizeof(image_data_directory));
    coff.symbols_count = 0;
    coff.symbol_table_offset = 0;
    std::memcpy(buf.data() + 68, &coff, sizeof(coff));

    // --- Optional header ---
    coff_optional_header_pe opt{};
    opt.magic = OH_MAGIC_PE32;
    opt.entry_point_address = 0x1000;
    opt.code_base = 0x1000;
    opt.data_base = 0x2000;
    std::memcpy(buf.data() + 88, &opt, sizeof(opt));

    // --- Win header ---
    win_header_pe win{};
    win.image_base = 0x00400000;
    win.section_alignment = 0x1000;
    win.file_alignment = 0x200;
    win.image_size = 0x3000;
    win.headers_size = 0x200;
    win.number_of_rva_and_sizes = 16;
    std::memcpy(buf.data() + 116, &win, sizeof(win));

    // --- Data directories (all zero — no imports etc.) ---
    // Already zeroed

    // --- Section header ---
    section_header sec{};
    std::memcpy(sec.name, ".text\0\0", 8);
    sec.virtual_size    = 16;
    sec.virtual_address = 0x1000;
    sec.data_size       = 16;
    sec.data_offset     = 352;
    sec.flags           = SCN_CNT_CODE | SCN_MEM_READ | SCN_MEM_EXECUTE;
    std::memcpy(buf.data() + 312, &sec, sizeof(sec));

    // --- Section data (some fake machine code) ---
    const uint8_t code[] = {
        0xCC, 0xCC, 0xCC, 0xCC,  // int3
        0x90, 0x90, 0x90, 0x90,  // nop
        0xC3, 0x00, 0x00, 0x00,  // ret
        0x00, 0x00, 0x00, 0x00
    };
    std::memcpy(buf.data() + 352, code, 16);

    return buf;
}

// ================================================================
//  coff_file<pe32_traits> tests
// ================================================================

TEST(CoffFileTest, ParseMinimalPE32) {
    auto buf = build_minimal_pe32();
    byte_view data(buf.data(), buf.size());

    auto file = coff_file<pe32_traits>::from_view(data);
    ASSERT_TRUE(file.has_value()) << to_string(file.error());

    EXPECT_TRUE(file->has_dos_header());
    EXPECT_EQ(file->section_count(), 1u);
}

TEST(CoffFileTest, DosHeader) {
    auto buf = build_minimal_pe32();
    byte_view data(buf.data(), buf.size());
    auto file = coff_file<pe32_traits>::from_view(data);
    ASSERT_TRUE(file.has_value());

    auto dos = file->dos_header();
    ASSERT_TRUE(dos.has_value());
    EXPECT_EQ(dos->pe_sign_location, 64);
}

TEST(CoffFileTest, CoffHeader) {
    auto buf = build_minimal_pe32();
    byte_view data(buf.data(), buf.size());
    auto file = coff_file<pe32_traits>::from_view(data);
    ASSERT_TRUE(file.has_value());

    auto hdr = file->coff_header();
    ASSERT_TRUE(hdr.has_value());
    EXPECT_EQ(hdr->machine, MACHINE_I386);
    EXPECT_EQ(hdr->sections_count, 1u);
}

TEST(CoffFileTest, OptionalHeader) {
    auto buf = build_minimal_pe32();
    byte_view data(buf.data(), buf.size());
    auto file = coff_file<pe32_traits>::from_view(data);
    ASSERT_TRUE(file.has_value());

    auto opt = file->optional_header();
    ASSERT_TRUE(opt.has_value());
    EXPECT_EQ(opt->magic, OH_MAGIC_PE32);
    EXPECT_EQ(opt->entry_point_address, 0x1000u);
}

TEST(CoffFileTest, WinHeader) {
    auto buf = build_minimal_pe32();
    byte_view data(buf.data(), buf.size());
    auto file = coff_file<pe32_traits>::from_view(data);
    ASSERT_TRUE(file.has_value());

    auto win = file->win_header();
    ASSERT_TRUE(win.has_value());
    EXPECT_EQ(win->image_base, 0x00400000u);
    EXPECT_EQ(win->section_alignment, 0x1000u);
    EXPECT_EQ(win->number_of_rva_and_sizes, 16u);
}

TEST(CoffFileTest, SectionIteration) {
    auto buf = build_minimal_pe32();
    byte_view data(buf.data(), buf.size());
    auto file = coff_file<pe32_traits>::from_view(data);
    ASSERT_TRUE(file.has_value());

    auto secs = file->sections();
    EXPECT_EQ(secs.size(), 1u);

    int count = 0;
    for (auto sec : secs) {
        EXPECT_EQ(sec.name(), ".text");
        EXPECT_EQ(sec.virtual_address(), 0x1000u);
        EXPECT_EQ(sec.data_size(), 16u);
        EXPECT_TRUE(sec.is_code());
        EXPECT_TRUE(sec.is_executable());

        // Verify we can read section data
        auto d = sec.data();
        EXPECT_EQ(d.size(), 16u);
        EXPECT_EQ(static_cast<uint8_t>(d[0]), 0xCC);
        ++count;
    }
    EXPECT_EQ(count, 1);
}

TEST(CoffFileTest, SectionFilterPipe) {
    auto buf = build_minimal_pe32();
    byte_view data(buf.data(), buf.size());
    auto file = coff_file<pe32_traits>::from_view(data);
    ASSERT_TRUE(file.has_value());

    // Use pipe syntax to find code sections
    auto code_secs = file->sections()
                     | filter([](auto s) { return s.is_code(); })
                     | transform([](auto s) { return s.name(); });

    std::vector<std::string_view> names;
    for (auto n : code_secs) names.push_back(n);
    ASSERT_EQ(names.size(), 1u);
    EXPECT_EQ(names[0], ".text");
}

TEST(CoffFileTest, EmptyImports) {
    auto buf = build_minimal_pe32();
    byte_view data(buf.data(), buf.size());
    auto file = coff_file<pe32_traits>::from_view(data);
    ASSERT_TRUE(file.has_value());

    auto imps = file->imports();
    // No import directory set → empty range
    int count = 0;
    for ([[maybe_unused]] auto m : imps) ++count;
    EXPECT_EQ(count, 0);
}

// ================================================================
//  Architecture detection tests
// ================================================================

TEST(DetectArchTest, DetectsPE32) {
    auto buf = build_minimal_pe32();
    byte_view data(buf.data(), buf.size());

    auto arch = detect_architecture(data);
    ASSERT_TRUE(arch.has_value());
    EXPECT_EQ(*arch, detected_arch::pe32);
}

TEST(DetectArchTest, DetectsPE32Plus) {
    // Modify the minimal PE to be PE32+
    auto buf = build_minimal_pe32();

    // Change optional header magic to PE32+
    coff_optional_header_pe_plus opt{};
    opt.magic = OH_MAGIC_PE32PLUS;
    opt.entry_point_address = 0x1000;
    opt.code_base = 0x1000;
    std::memcpy(buf.data() + 88, &opt, sizeof(opt));

    // Update COFF header optional_header_size
    uint16_t new_opt_size = static_cast<uint16_t>(
        sizeof(coff_optional_header_pe_plus) + sizeof(win_header_pe_plus) +
        16 * sizeof(image_data_directory));
    std::memcpy(buf.data() + 68 + 16, &new_opt_size, sizeof(new_opt_size));

    byte_view data(buf.data(), buf.size());
    auto arch = detect_architecture(data);
    ASSERT_TRUE(arch.has_value());
    EXPECT_EQ(*arch, detected_arch::pe32plus);
}

TEST(DetectArchTest, TooSmallFile) {
    const char tiny[] = "MZ";
    byte_view data(tiny, 2);
    auto arch = detect_architecture(data);
    EXPECT_FALSE(arch.has_value());
}

// ================================================================
//  auto_load tests
// ================================================================

TEST(AutoLoadTest, LoadsPE32) {
    auto buf = build_minimal_pe32();
    byte_view data(buf.data(), buf.size());

    auto file = auto_load(data);
    ASSERT_TRUE(file.has_value());
    EXPECT_TRUE(std::holds_alternative<coff_file<pe32_traits>>(*file));
}

// ================================================================
//  Error handling: malformed files
// ================================================================

TEST(CoffFileTest, InvalidMagicRejectsWrongTraits) {
    auto buf = build_minimal_pe32();
    byte_view data(buf.data(), buf.size());

    // Try to load a PE32 file as PE32+ — should fail with invalid_magic
    auto file = coff_file<pe32plus_traits>::from_view(data);
    EXPECT_FALSE(file.has_value());
    EXPECT_EQ(file.error(), error_code::invalid_magic);
}

TEST(CoffFileTest, TruncatedFile) {
    auto buf = build_minimal_pe32();
    buf.resize(10);  // Truncate below sizeof(coff_file_header)
    byte_view data(buf.data(), buf.size());

    auto file = coff_file<pe32_traits>::from_view(data);
    EXPECT_FALSE(file.has_value());
}
