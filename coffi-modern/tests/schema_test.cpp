#include <gtest/gtest.h>
#include <coffi/platform/schema.hpp>
#include <cstddef>

using namespace coffi;

// These duplicate the static_asserts in schema.hpp but serve as
// executable proof and catch accidental pragma pack changes.

TEST(SchemaTest, StructSizes) {
    EXPECT_EQ(sizeof(msdos_header),                  64u);
    EXPECT_EQ(sizeof(coff_file_header),              20u);
    EXPECT_EQ(sizeof(coff_optional_header_pe),       28u);
    EXPECT_EQ(sizeof(coff_optional_header_pe_plus),  24u);
    EXPECT_EQ(sizeof(win_header_pe),                 68u);
    EXPECT_EQ(sizeof(win_header_pe_plus),            88u);
    EXPECT_EQ(sizeof(image_data_directory),            8u);
    EXPECT_EQ(sizeof(section_header),                40u);
    EXPECT_EQ(sizeof(symbol_record),                 18u);
    EXPECT_EQ(sizeof(auxiliary_symbol_record),        18u);
    EXPECT_EQ(sizeof(auxiliary_symbol_record_5),      18u);
    EXPECT_EQ(sizeof(rel_entry),                     10u);
    EXPECT_EQ(sizeof(line_number_entry),              6u);
    EXPECT_EQ(sizeof(image_import_descriptor),       20u);
    EXPECT_EQ(sizeof(image_import_by_name),           2u);
}

TEST(SchemaTest, CriticalFieldOffsets) {
    // DOS header: pe_sign_location at offset 60
    EXPECT_EQ(offsetof(msdos_header, pe_sign_location), 60u);

    // COFF header: symbol_table_offset at offset 8
    EXPECT_EQ(offsetof(coff_file_header, symbol_table_offset), 8u);
    EXPECT_EQ(offsetof(coff_file_header, sections_count), 2u);

    // Section header: data_offset at offset 20
    EXPECT_EQ(offsetof(section_header, data_offset), 20u);
    EXPECT_EQ(offsetof(section_header, flags), 36u);

    // Symbol record: storage_class at offset 16
    EXPECT_EQ(offsetof(symbol_record, storage_class), 16u);
    EXPECT_EQ(offsetof(symbol_record, aux_symbols_number), 17u);

    // Import descriptor: name at offset 12
    EXPECT_EQ(offsetof(image_import_descriptor, name), 12u);
}

TEST(SchemaTest, MagicConstants) {
    EXPECT_EQ(OH_MAGIC_PE32,     0x010Bu);
    EXPECT_EQ(OH_MAGIC_PE32PLUS, 0x020Bu);
    EXPECT_EQ(PE_SIGNATURE,      0x00004550u);
}
