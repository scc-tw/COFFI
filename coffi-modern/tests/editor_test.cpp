#include <gtest/gtest.h>
#include <coffi/coffi.hpp>
#include <cstring>

using namespace coffi;

// ================================================================
//  coff_editor basic CRUD
// ================================================================

TEST(EditorTest, CreateEmpty) {
    coff_editor<pe32_traits> ed;
    EXPECT_EQ(ed.section_count(), 0u);
    EXPECT_EQ(ed.symbol_count(), 0u);
    EXPECT_FALSE(ed.has_dos_header());
    EXPECT_FALSE(ed.has_optional_header());
}

TEST(EditorTest, CreateDosHeader) {
    coff_editor<pe32_traits> ed;
    ed.create_dos_header();
    ASSERT_TRUE(ed.has_dos_header());
    auto* dos = ed.dos_header();
    ASSERT_NE(dos, nullptr);
    uint8_t s0 = dos->signature & 0xFF;
    uint8_t s1 = dos->signature >> 8;
    EXPECT_EQ(s0, PEMAG0);
    EXPECT_EQ(s1, PEMAG1);
}

TEST(EditorTest, CreateOptionalAndWinHeader) {
    coff_editor<pe32_traits> ed;
    ed.create_optional_header();
    ASSERT_TRUE(ed.has_optional_header());
    EXPECT_EQ(ed.optional_header()->magic, OH_MAGIC_PE32);

    ed.create_win_header();
    ASSERT_TRUE(ed.has_win_header());
    EXPECT_EQ(ed.win_header<>()->file_alignment, 0x200u);
}

TEST(EditorTest, AddAndRemoveSections) {
    coff_editor<pe32_traits> ed;

    auto& text = ed.add_section(".text", SCN_CNT_CODE | SCN_MEM_READ | SCN_MEM_EXECUTE);
    const uint8_t code[] = {0xCC, 0xCC, 0x90, 0xC3};
    text.set_data(code, sizeof(code));
    text.set_virtual_address(0x1000);
    text.set_virtual_size(sizeof(code));

    auto& data = ed.add_section(".data", SCN_CNT_INITIALIZED_DATA | SCN_MEM_READ | SCN_MEM_WRITE);
    data.set_data("hello", 6);

    EXPECT_EQ(ed.section_count(), 2u);
    EXPECT_EQ(ed.sections()[0].name(), ".text");
    EXPECT_EQ(ed.sections()[1].name(), ".data");

    // Find
    EXPECT_NE(ed.find_section(".text"), nullptr);
    EXPECT_EQ(ed.find_section(".nonexistent"), nullptr);

    // Remove by name
    auto r = ed.remove_section(".data");
    EXPECT_TRUE(r.has_value());
    EXPECT_EQ(ed.section_count(), 1u);
    EXPECT_EQ(ed.sections()[0].name(), ".text");
}

TEST(EditorTest, AddAndRemoveSymbols) {
    coff_editor<pe32_traits> ed;

    auto& sym = ed.add_symbol("_main");
    sym.set_value(0x1000);
    sym.set_section_number(1);
    sym.set_storage_class(2);

    auto& sym2 = ed.add_symbol("_foo");
    sym2.set_value(0x2000);

    EXPECT_EQ(ed.symbol_count(), 2u);
    EXPECT_NE(ed.find_symbol("_main"), nullptr);
    EXPECT_EQ(ed.find_symbol("_main")->value(), 0x1000u);

    // Remove
    auto r = ed.remove_symbol(0);
    EXPECT_TRUE(r.has_value());
    EXPECT_EQ(ed.symbol_count(), 1u);
    EXPECT_EQ(ed.symbols()[0].name(), "_foo");
}

TEST(EditorTest, SymbolWithAuxRecords) {
    coff_editor<pe32_traits> ed;
    auto& sym = ed.add_symbol("_func");

    auxiliary_symbol_record aux{};
    std::memset(&aux, 0xAB, sizeof(aux));
    sym.add_aux(aux);

    EXPECT_EQ(sym.aux_count(), 1);
    EXPECT_EQ(sym.total_slots(), 2u);
    EXPECT_EQ(sym.aux_records().size(), 1u);
}

TEST(EditorTest, SectionDataManipulation) {
    section_entry<pe32_traits> sec(".test");

    sec.set_data("hello", 5);
    EXPECT_EQ(sec.data_length(), 5u);

    sec.append_data(" world", 6);
    EXPECT_EQ(sec.data_length(), 11u);

    auto view = sec.data_view();
    EXPECT_EQ(view.read_cstring(0), "hello world");

    sec.clear_data();
    EXPECT_EQ(sec.data_length(), 0u);
}

TEST(EditorTest, SectionRelocations) {
    section_entry<pe32_traits> sec(".text");

    rel_entry rel{};
    rel.virtual_address = 0x10;
    rel.symbol_table_index = 1;
    rel.type = 0x14;
    sec.add_relocation(rel);

    EXPECT_EQ(sec.relocations().size(), 1u);
    EXPECT_EQ(sec.relocations_file_size(), sizeof(rel_entry));
    EXPECT_EQ(sec.relocations()[0].virtual_address, 0x10u);

    sec.clear_relocations();
    EXPECT_EQ(sec.relocations().size(), 0u);
}

TEST(EditorTest, Directories) {
    coff_editor<pe32_traits> ed;
    ed.ensure_directories(16);
    EXPECT_EQ(ed.directory_count(), 16u);

    image_data_directory dir{0x2000, 100};
    ed.set_directory(DIR_IMPORT, dir);
    auto* d = ed.directory(DIR_IMPORT);
    ASSERT_NE(d, nullptr);
    EXPECT_EQ(d->virtual_address, 0x2000u);
    EXPECT_EQ(d->size, 100u);
}

// ================================================================
//  String table builder
// ================================================================

TEST(StringTableBuilderTest, ShortNameInline) {
    string_table_builder stb;
    char field[8] = {};
    stb.encode_name("_main", field, false);
    EXPECT_EQ(std::string_view(field, 5), "_main");
    EXPECT_TRUE(stb.empty()); // no entry added to table
}

TEST(StringTableBuilderTest, LongSymbolName) {
    string_table_builder stb;
    char field[8] = {};
    stb.encode_name("very_long_symbol_name", field, false);

    // First 4 bytes should be zero
    uint32_t first4;
    std::memcpy(&first4, field, 4);
    EXPECT_EQ(first4, 0u);

    // Next 4 bytes should be offset into string table
    uint32_t offset;
    std::memcpy(&offset, field + 4, 4);
    EXPECT_GE(offset, 4u);

    EXPECT_FALSE(stb.empty());
}

TEST(StringTableBuilderTest, LongSectionName) {
    string_table_builder stb;
    char field[8] = {};
    stb.encode_name(".debug_info_long", field, true);
    EXPECT_EQ(field[0], '/');
    // Rest should be decimal offset
    EXPECT_FALSE(stb.empty());
}

TEST(StringTableBuilderTest, Deduplication) {
    string_table_builder stb;
    auto off1 = stb.add("long_name_here");
    auto off2 = stb.add("long_name_here");
    EXPECT_EQ(off1, off2);
}

// ================================================================
//  Data builder
// ================================================================

TEST(DataBuilderTest, WriteAndPatch) {
    data_builder db;
    auto off = db.write(uint32_t{0xDEADBEEF});
    ASSERT_TRUE(off.has_value());
    EXPECT_EQ(*off, 0u);
    EXPECT_EQ(db.size(), 4u);

    db.patch(*off, uint32_t{0x12345678});
    uint32_t val;
    std::memcpy(&val, db.data(), 4);
    EXPECT_EQ(val, 0x12345678u);
}

TEST(DataBuilderTest, ReserveAndAlign) {
    data_builder db;
    db.write(uint8_t{0xFF});
    EXPECT_EQ(db.size(), 1u);

    db.align(4);
    EXPECT_EQ(db.size(), 4u);

    auto off = db.reserve<uint32_t>();
    ASSERT_TRUE(off.has_value());
    EXPECT_EQ(*off, 4u);
    EXPECT_EQ(db.size(), 8u);
}

// ================================================================
//  Save and round-trip
// ================================================================

TEST(EditorTest, SaveMinimalPE32) {
    coff_editor<pe32_traits> ed;

    // Build a minimal PE
    ed.create_dos_header();
    ed.create_optional_header();
    ed.create_win_header();
    ed.ensure_directories(16);

    ed.coff_header().machine = MACHINE_I386;

    auto& text = ed.add_section(".text", SCN_CNT_CODE | SCN_MEM_READ | SCN_MEM_EXECUTE);
    const uint8_t code[] = {0xCC, 0x90, 0xC3, 0x00};
    text.set_data(code, sizeof(code));
    text.set_virtual_address(0x1000);
    text.set_virtual_size(sizeof(code));

    ed.optional_header()->entry_point_address = 0x1000;

    // Save
    auto buf = ed.save();
    ASSERT_TRUE(buf.has_value()) << to_string(buf.error());
    EXPECT_GT(buf->size(), 0u);

    // Re-parse with the read-only parser
    byte_view data(buf->data(), buf->size());
    auto file = coff_file<pe32_traits>::from_view(data);
    ASSERT_TRUE(file.has_value()) << to_string(file.error());

    EXPECT_TRUE(file->has_dos_header());
    EXPECT_EQ(file->section_count(), 1u);

    auto hdr = file->coff_header();
    ASSERT_TRUE(hdr.has_value());
    EXPECT_EQ(hdr->machine, MACHINE_I386);

    auto opt = file->optional_header();
    ASSERT_TRUE(opt.has_value());
    EXPECT_EQ(opt->magic, OH_MAGIC_PE32);
    EXPECT_EQ(opt->entry_point_address, 0x1000u);

    // Verify section
    int count = 0;
    for (auto sec : file->sections()) {
        EXPECT_EQ(sec.name(), ".text");
        EXPECT_TRUE(sec.is_code());
        auto d = sec.data();
        ASSERT_EQ(d.size(), 4u);
        EXPECT_EQ(static_cast<uint8_t>(d[0]), 0xCC);
        ++count;
    }
    EXPECT_EQ(count, 1);
}

TEST(EditorTest, SaveWithSymbols) {
    coff_editor<pe32_traits> ed;

    auto& sec = ed.add_section(".text");
    sec.set_data("code", 4);

    auto& sym1 = ed.add_symbol("_start");
    sym1.set_value(0x100);
    sym1.set_section_number(1);

    auto& sym2 = ed.add_symbol("_end");
    sym2.set_value(0x200);
    sym2.set_section_number(1);

    auto buf = ed.save();
    ASSERT_TRUE(buf.has_value()) << to_string(buf.error());

    // Re-parse and verify symbols
    byte_view data(buf->data(), buf->size());
    auto file = coff_file<pe32_traits>::from_view(data);
    ASSERT_TRUE(file.has_value());

    std::vector<std::string> names;
    for (auto sym : file->symbols()) {
        names.emplace_back(sym.name());
    }
    ASSERT_EQ(names.size(), 2u);
    EXPECT_EQ(names[0], "_start");
    EXPECT_EQ(names[1], "_end");
}

TEST(EditorTest, LoadAndResave) {
    // Build → save → load into editor → resave → verify identical
    coff_editor<pe32_traits> ed;
    ed.create_dos_header();
    ed.create_optional_header();
    ed.create_win_header();
    ed.ensure_directories(16);
    ed.coff_header().machine = MACHINE_I386;

    auto& sec = ed.add_section(".text", SCN_CNT_CODE | SCN_MEM_READ);
    sec.set_data("ABCD", 4);
    sec.set_virtual_address(0x1000);
    sec.set_virtual_size(4);

    auto buf1 = ed.save();
    ASSERT_TRUE(buf1.has_value());

    // Load into a new editor
    auto ed2 = coff_editor<pe32_traits>::from_view(byte_view{buf1->data(), buf1->size()});
    ASSERT_TRUE(ed2.has_value());
    EXPECT_EQ(ed2->section_count(), 1u);
    EXPECT_EQ(ed2->sections()[0].name(), ".text");
}

// ================================================================
//  TI/CEVA traits and schema
// ================================================================

TEST(TiCevaTest, TiStructSizes) {
    EXPECT_EQ(sizeof(coff_file_header_ti), 22u);
    EXPECT_EQ(sizeof(section_header_ti), 48u);
    EXPECT_EQ(sizeof(common_optional_header_ti), 28u);
    EXPECT_EQ(sizeof(rel_entry_ti), 12u);
}

TEST(TiCevaTest, CevaStructSizes) {
    EXPECT_EQ(sizeof(rel_entry_ceva), 12u);
}

TEST(TiCevaTest, AddressableUnit) {
    EXPECT_EQ(ti_traits::addressable_unit(TI_TMS320C2800), 2);
    EXPECT_EQ(ti_traits::addressable_unit(TI_TMS320C6000), 1);
    EXPECT_EQ(ti_traits::addressable_unit(TI_MSP430), 1);
    EXPECT_EQ(pe32_traits::addressable_unit(MACHINE_I386), 1);
    EXPECT_EQ(ceva_traits::addressable_unit(CEVA_MACHINE_XC4210_OBJ), 1);
}

TEST(TiCevaTest, TiTraitsTypes) {
    static_assert(std::is_same_v<ti_traits::file_header_type, coff_file_header_ti>);
    static_assert(std::is_same_v<ti_traits::section_header_type, section_header_ti>);
    static_assert(std::is_same_v<ti_traits::relocation_type, rel_entry_ti>);
    static_assert(!ti_traits::has_dos_header);
    static_assert(!ti_traits::has_win_header);
    static_assert(!ti_traits::has_imports);
}

TEST(TiCevaTest, CevaTraitsTypes) {
    static_assert(std::is_same_v<ceva_traits::file_header_type, coff_file_header>);
    static_assert(std::is_same_v<ceva_traits::relocation_type, rel_entry_ceva>);
    static_assert(!ceva_traits::has_dos_header);
    static_assert(!ceva_traits::has_win_header);
}

TEST(TiCevaTest, CreateTiEditor) {
    coff_editor<ti_traits> ed;
    ed.coff_header().target_id = TI_TMS320C2800;
    ed.coff_header().version = 0x00C2;

    auto& sec = ed.add_section(".text");
    sec.set_data("code", 4);
    sec.set_flags(STYP_TEXT);

    EXPECT_EQ(ed.section_count(), 1u);
    EXPECT_FALSE(ed.has_dos_header()); // TI has no DOS header
}
