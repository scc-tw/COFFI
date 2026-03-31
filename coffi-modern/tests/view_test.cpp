#include <gtest/gtest.h>
#include <coffi/core/byte_view.hpp>
#include <coffi/platform/schema.hpp>
#include <coffi/platform/traits.hpp>
#include <coffi/views/string_table.hpp>
#include <coffi/views/section_view.hpp>
#include <coffi/views/symbol_view.hpp>
#include <coffi/views/rva_resolver.hpp>
#include <coffi/core/lazy.hpp>
#include <cstring>
#include <vector>

using namespace coffi;

// ================================================================
//  Helper: build a byte buffer from packed structs
// ================================================================

class buffer_builder {
    std::vector<char> buf_;
public:
    template <typename T>
    std::size_t write(const T& val) {
        static_assert(std::is_trivially_copyable_v<T>);
        auto off = buf_.size();
        buf_.resize(off + sizeof(T));
        std::memcpy(buf_.data() + off, &val, sizeof(T));
        return off;
    }
    std::size_t write_bytes(const void* data, std::size_t len) {
        auto off = buf_.size();
        buf_.resize(off + len);
        std::memcpy(buf_.data() + off, data, len);
        return off;
    }
    std::size_t write_zeros(std::size_t len) {
        auto off = buf_.size();
        buf_.resize(off + len, 0);
        return off;
    }
    byte_view view() const { return {buf_.data(), buf_.size()}; }
    std::size_t size() const { return buf_.size(); }
    char* data() { return buf_.data(); }
};

// ================================================================
//  section_range tests
// ================================================================

TEST(SectionViewTest, IterateSections) {
    buffer_builder bb;

    section_header h1{};
    std::memcpy(h1.name, ".text\0\0", 8);
    h1.virtual_size    = 0x1000;
    h1.virtual_address = 0x1000;
    h1.data_size       = 512;
    h1.data_offset     = 200;
    h1.flags           = SCN_CNT_CODE | SCN_MEM_READ | SCN_MEM_EXECUTE;
    auto off1 = bb.write(h1);

    section_header h2{};
    std::memcpy(h2.name, ".data\0\0", 8);
    h2.virtual_size    = 0x500;
    h2.virtual_address = 0x2000;
    h2.data_size       = 256;
    h2.data_offset     = 712;
    h2.flags           = SCN_CNT_INITIALIZED_DATA | SCN_MEM_READ | SCN_MEM_WRITE;
    bb.write(h2);

    // Pad buffer to cover the fake section data offsets
    bb.write_zeros(1024);

    section_range<pe32_traits> range(bb.view(), off1, 2);
    EXPECT_EQ(range.size(), 2u);

    int idx = 0;
    for (auto sec : range) {
        if (idx == 0) {
            EXPECT_EQ(sec.name(), ".text");
            EXPECT_EQ(sec.virtual_address(), 0x1000u);
            EXPECT_TRUE(sec.is_code());
            EXPECT_TRUE(sec.is_executable());
            EXPECT_FALSE(sec.is_writable());
        } else {
            EXPECT_EQ(sec.name(), ".data");
            EXPECT_TRUE(sec.is_data());
            EXPECT_TRUE(sec.is_writable());
            EXPECT_FALSE(sec.is_code());
        }
        ++idx;
    }
    EXPECT_EQ(idx, 2);
}

TEST(SectionViewTest, IndexOperator) {
    buffer_builder bb;
    section_header h{};
    std::memcpy(h.name, ".rdata\0", 8);
    h.virtual_size = 100;
    auto off = bb.write(h);
    bb.write_zeros(100);

    section_range<pe32_traits> range(bb.view(), off, 1);
    auto sec = range[0];
    EXPECT_EQ(sec.name(), ".rdata");
    EXPECT_EQ(sec.virtual_size(), 100u);
}

TEST(SectionViewTest, FilterWithPipe) {
    buffer_builder bb;

    section_header h1{};
    std::memcpy(h1.name, ".text\0\0", 8);
    h1.flags = SCN_CNT_CODE | SCN_MEM_READ | SCN_MEM_EXECUTE;
    auto off = bb.write(h1);

    section_header h2{};
    std::memcpy(h2.name, ".data\0\0", 8);
    h2.flags = SCN_CNT_INITIALIZED_DATA | SCN_MEM_READ;
    bb.write(h2);
    bb.write_zeros(100);

    section_range<pe32_traits> range(bb.view(), off, 2);
    auto code_sections = range | filter([](auto s) { return s.is_code(); });

    int count = 0;
    for (auto sec : code_sections) {
        EXPECT_EQ(sec.name(), ".text");
        ++count;
    }
    EXPECT_EQ(count, 1);
}

// ================================================================
//  string_table_view tests
// ================================================================

TEST(StringTableTest, ResolveInlineName) {
    // No string table needed for inline names
    string_table_view st;
    char name[8] = {'_', 'm', 'a', 'i', 'n', '\0', '\0', '\0'};
    EXPECT_EQ(st.resolve_name(name), "_main");
}

TEST(StringTableTest, ResolveLongName) {
    // Build a string table: [4-byte size][strings...]
    buffer_builder bb;
    uint32_t table_size = 30;  // total size including this field
    bb.write(table_size);
    // String at offset 4: "short_name_that_is_longer_than_8"
    const char long_name[] = "very_long_symbol_name";
    bb.write_bytes(long_name, sizeof(long_name));

    string_table_view st(bb.view());

    // Symbol name field: first 4 bytes = 0, next 4 bytes = offset 4
    char name[8] = {};
    uint32_t zero = 0, offset = 4;
    std::memcpy(name, &zero, 4);
    std::memcpy(name + 4, &offset, 4);

    EXPECT_EQ(st.resolve_name(name), "very_long_symbol_name");
}

TEST(StringTableTest, SectionSlashName) {
    buffer_builder bb;
    uint32_t table_size = 20;
    bb.write(table_size);
    const char long_name[] = ".debug_info";
    bb.write_bytes(long_name, sizeof(long_name));

    string_table_view st(bb.view());

    // Section name: "/4" (offset 4 in string table)
    char name[8] = {'/', '4', '\0', '\0', '\0', '\0', '\0', '\0'};
    EXPECT_EQ(st.resolve_name(name), ".debug_info");
}

// ================================================================
//  symbol_range tests
// ================================================================

TEST(SymbolViewTest, IterateSymbols) {
    buffer_builder bb;

    // Build string table first (for reference)
    buffer_builder stb;
    uint32_t st_size = 4 + 10;  // size field + string
    stb.write(st_size);
    stb.write_bytes("long_sym\0", 10);
    string_table_view st(stb.view());

    // Symbol 1: inline name "foo"
    symbol_record s1{};
    std::memcpy(s1.name, "foo\0\0\0\0", 8);
    s1.value = 0x100;
    s1.section_number = 1;
    s1.storage_class = 2;
    s1.aux_symbols_number = 0;
    auto off = bb.write(s1);

    // Symbol 2: has 1 aux record
    symbol_record s2{};
    std::memcpy(s2.name, "bar\0\0\0\0", 8);
    s2.value = 0x200;
    s2.section_number = 1;
    s2.aux_symbols_number = 1;
    bb.write(s2);

    // Aux record (18 bytes of zeros)
    auxiliary_symbol_record aux{};
    bb.write(aux);

    // Symbol 3: inline name "baz"
    symbol_record s3{};
    std::memcpy(s3.name, "baz\0\0\0\0", 8);
    s3.value = 0x300;
    s3.aux_symbols_number = 0;
    bb.write(s3);

    // 4 total records (s1 + s2 + aux + s3)
    symbol_range range(bb.view(), off, 4, &st);

    std::vector<std::string> names;
    std::vector<uint32_t> values;
    for (auto sym : range) {
        names.emplace_back(sym.name());
        values.push_back(sym.value());
    }

    // Iterator should skip aux records: we get 3 symbols
    ASSERT_EQ(names.size(), 3u);
    EXPECT_EQ(names[0], "foo");
    EXPECT_EQ(names[1], "bar");
    EXPECT_EQ(names[2], "baz");
    EXPECT_EQ(values[0], 0x100u);
    EXPECT_EQ(values[1], 0x200u);
    EXPECT_EQ(values[2], 0x300u);
}

// ================================================================
//  rva_resolver tests
// ================================================================

TEST(RvaResolverTest, ResolvesCorrectly) {
    buffer_builder bb;

    // One section: VA 0x1000, raw data at offset 512, size 256
    section_header h{};
    h.virtual_address = 0x1000;
    h.virtual_size    = 256;
    h.data_size       = 256;
    h.data_offset     = 512;
    auto sec_off = bb.write(h);

    // Pad to cover the section data area
    bb.write_zeros(1024);

    rva_resolver resolver(bb.view(), sec_off, 1);

    // RVA 0x1000 should map to file offset 512
    auto r1 = resolver.resolve(0x1000);
    ASSERT_TRUE(r1.has_value());
    EXPECT_EQ(*r1, 512u);

    // RVA 0x1010 should map to file offset 512 + 0x10 = 528
    auto r2 = resolver.resolve(0x1010);
    ASSERT_TRUE(r2.has_value());
    EXPECT_EQ(*r2, 528u);

    // RVA outside section should fail
    auto r3 = resolver.resolve(0x2000);
    EXPECT_FALSE(r3.has_value());
    EXPECT_EQ(r3.error(), error_code::invalid_rva);
}

TEST(RvaResolverTest, ReadString) {
    buffer_builder bb;

    section_header h{};
    h.virtual_address = 0x1000;
    h.virtual_size    = 256;
    h.data_size       = 256;
    h.data_offset     = 512;
    auto sec_off = bb.write(h);

    // Pad up to offset 512
    bb.write_zeros(512 - bb.size());
    // Write a string at file offset 512 (= RVA 0x1000)
    bb.write_bytes("hello.dll\0", 10);
    bb.write_zeros(256 - 10);

    rva_resolver resolver(bb.view(), sec_off, 1);

    auto s = resolver.read_string(0x1000);
    ASSERT_TRUE(s.has_value());
    EXPECT_EQ(*s, "hello.dll");
}
