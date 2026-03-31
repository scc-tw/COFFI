#ifdef _MSC_VER
#define _SCL_SECURE_NO_WARNINGS
#endif

#define BOOST_TEST_MAIN
#ifndef _MSC_VER
#define BOOST_TEST_DYN_LINK
#endif
#define BOOST_TEST_MODULE COFFI_import_test

#include <boost/test/unit_test.hpp>

#include <coffi/coffi.hpp>
#include <sstream>
#include <cstring>

using namespace COFFI;

//------------------------------------------------------------------------------
// Helper: initialize a coffi as a minimal PE32 image suitable for import tests.
static void init_minimal_pe(coffi& c, uint16_t magic = OH_MAGIC_PE32)
{
    c.create(COFFI_ARCHITECTURE_PE);
    c.create_optional_header(magic);

    c.get_header()->set_flags(IMAGE_FILE_EXECUTABLE_IMAGE |
                              IMAGE_FILE_32BIT_MACHINE);
    if (magic == OH_MAGIC_PE32PLUS) {
        c.get_header()->set_machine(IMAGE_FILE_MACHINE_AMD64);
    }
    else {
        c.get_header()->set_machine(IMAGE_FILE_MACHINE_I386);
    }
    c.get_optional_header()->set_entry_point_address(0x1000);
    c.get_win_header()->set_image_base(0x00400000);
    c.get_win_header()->set_section_alignment(0x1000);
    c.get_win_header()->set_file_alignment(0x200);
    c.get_win_header()->set_major_os_version(6);
    c.get_win_header()->set_major_subsystem_version(6);
    c.get_win_header()->set_subsystem(3); // CUI
    c.get_win_header()->set_stack_reserve_size(0x100000);
    c.get_win_header()->set_stack_commit_size(0x1000);
    c.get_win_header()->set_heap_reserve_size(0x100000);
    c.get_win_header()->set_heap_commit_size(0x1000);

    // Add a minimal .text section
    section* text = c.add_section(".text");
    char code[] = {'\xCC'}; // int3
    text->set_data(code, sizeof(code));
    text->set_virtual_address(0x1000);
    text->set_virtual_size(sizeof(code));
    text->set_flags(IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ |
                    IMAGE_SCN_CNT_CODE);

    // Add 16 data directories (standard PE)
    for (int i = 0; i < 16; ++i) {
        c.add_directory(image_data_directory{0, 0});
    }
}

//------------------------------------------------------------------------------
// Helper: save to memory, reload into a fresh coffi.
static bool round_trip(coffi& src, coffi& dst)
{
    std::stringstream ss(std::ios::in | std::ios::out | std::ios::binary);
    if (!src.save(ss))
        return false;
    ss.seekg(0);
    return dst.load(ss);
}

//==============================================================================
// READ TESTS — verify parsing of existing imports
//==============================================================================

BOOST_AUTO_TEST_CASE(read_imports_pe32plus)
{
    coffi c;
    BOOST_REQUIRE_EQUAL(c.load("data/notepad.exe"), true);

    // notepad.exe is PE32+ (AMD64)
    BOOST_REQUIRE_NE(c.get_optional_header(), (void*)0);
    BOOST_CHECK_EQUAL(c.get_optional_header()->get_magic(), OH_MAGIC_PE32PLUS);

    import_section_accessor imports(c);
    uint32_t count = imports.get_import_count();
    BOOST_CHECK_GT(count, 0u);

    // Verify we can read at least one DLL name and symbol
    std::string dll = imports.get_dll_name(0);
    BOOST_CHECK(!dll.empty());

    uint32_t sym_count = imports.get_symbol_count(0);
    BOOST_CHECK_GT(sym_count, 0u);

    std::string sym_name;
    uint16_t    hint;
    BOOST_CHECK_EQUAL(imports.get_symbol(0, 0, sym_name, hint), true);
    BOOST_CHECK(!sym_name.empty());
}

//------------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(read_imports_pe32)
{
    coffi c;
    BOOST_REQUIRE_EQUAL(c.load("data/espui.dll"), true);

    BOOST_REQUIRE_NE(c.get_optional_header(), (void*)0);
    BOOST_CHECK_EQUAL(c.get_optional_header()->get_magic(), OH_MAGIC_PE32);

    import_section_accessor imports(c);
    uint32_t count = imports.get_import_count();
    BOOST_CHECK_GT(count, 0u);

    // Structured API
    const auto& mods = imports.get_imports();
    BOOST_CHECK_EQUAL(mods.size(), count);

    for (const auto& mod : mods) {
        BOOST_CHECK(!mod.dll_name.empty());
    }
}

//------------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(read_imports_empty_pe)
{
    coffi c;
    init_minimal_pe(c);

    import_section_accessor imports(c);
    BOOST_CHECK_EQUAL(imports.get_import_count(), 0u);
    BOOST_CHECK_EQUAL(imports.get_dll_name(0), "");
    BOOST_CHECK_EQUAL(imports.get_symbol_count(0), 0u);
}

//------------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(read_imports_out_of_range)
{
    coffi c;
    BOOST_REQUIRE_EQUAL(c.load("data/notepad.exe"), true);

    import_section_accessor imports(c);
    uint32_t count = imports.get_import_count();

    // Out of range access should return safe defaults
    BOOST_CHECK_EQUAL(imports.get_dll_name(count), "");
    BOOST_CHECK_EQUAL(imports.get_dll_name(count + 100), "");
    BOOST_CHECK_EQUAL(imports.get_symbol_count(count), 0u);

    std::string name;
    uint16_t    hint;
    BOOST_CHECK_EQUAL(imports.get_symbol(count, 0, name, hint), false);
    BOOST_CHECK_EQUAL(imports.get_symbol(0, 99999, name, hint), false);
}

//==============================================================================
// WRITE TESTS — add imports and verify round-trip
//==============================================================================

BOOST_AUTO_TEST_CASE(add_single_import_pe32)
{
    coffi c;
    init_minimal_pe(c, OH_MAGIC_PE32);

    import_section_accessor imports(c);
    BOOST_CHECK_EQUAL(
        imports.add_import("test_runtime.dll", "test_entry", 0), true);

    // Verify in-memory (re-parse after add)
    BOOST_CHECK_EQUAL(imports.get_import_count(), 1u);
    BOOST_CHECK_EQUAL(imports.get_dll_name(0), "test_runtime.dll");
    BOOST_CHECK_EQUAL(imports.get_symbol_count(0), 1u);

    std::string name;
    uint16_t    hint;
    BOOST_CHECK_EQUAL(imports.get_symbol(0, 0, name, hint), true);
    BOOST_CHECK_EQUAL(name, "test_entry");
    BOOST_CHECK_EQUAL(hint, 0);

    // Round-trip: save and reload
    coffi c2;
    BOOST_REQUIRE(round_trip(c, c2));

    import_section_accessor imports2(c2);
    BOOST_CHECK_EQUAL(imports2.get_import_count(), 1u);
    BOOST_CHECK_EQUAL(imports2.get_dll_name(0), "test_runtime.dll");
    BOOST_CHECK_EQUAL(imports2.get_symbol_count(0), 1u);

    BOOST_CHECK_EQUAL(imports2.get_symbol(0, 0, name, hint), true);
    BOOST_CHECK_EQUAL(name, "test_entry");
}

//------------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(add_single_import_pe32plus)
{
    coffi c;
    init_minimal_pe(c, OH_MAGIC_PE32PLUS);

    import_section_accessor imports(c);
    BOOST_CHECK_EQUAL(
        imports.add_import("vmpilot_runtime.dll", "vm_stub_entry", 0), true);

    // Round-trip
    coffi c2;
    BOOST_REQUIRE(round_trip(c, c2));

    // Verify PE32+ was preserved
    BOOST_REQUIRE_NE(c2.get_optional_header(), (void*)0);
    BOOST_CHECK_EQUAL(c2.get_optional_header()->get_magic(), OH_MAGIC_PE32PLUS);

    import_section_accessor imports2(c2);
    BOOST_CHECK_EQUAL(imports2.get_import_count(), 1u);
    BOOST_CHECK_EQUAL(imports2.get_dll_name(0), "vmpilot_runtime.dll");

    std::string name;
    uint16_t    hint;
    BOOST_CHECK_EQUAL(imports2.get_symbol(0, 0, name, hint), true);
    BOOST_CHECK_EQUAL(name, "vm_stub_entry");

    // Verify thunks are 8 bytes: the .idata section should be larger than
    // for PE32 with the same content (due to 8-byte thunks vs 4-byte).
    section* idata = c2.get_sections()[".idata"];
    BOOST_REQUIRE_NE(idata, (section*)0);
    // IDT(2*20) + ILT(8+8) + IAT(8+8) + IBN(2+len+1+pad) + DLLname
    // = 40 + 16 + 16 + align + names > 40 + 8 + 8 (PE32 thunks)
    BOOST_CHECK_GT(idata->get_data_size(), 40u + 16u);
}

//------------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(add_multiple_imports_different_dlls)
{
    coffi c;
    init_minimal_pe(c, OH_MAGIC_PE32);

    import_section_accessor imports(c);
    BOOST_CHECK_EQUAL(imports.add_import("kernel32.dll", "ExitProcess"), true);
    BOOST_CHECK_EQUAL(imports.add_import("user32.dll", "MessageBoxA"), true);

    // After second add_import, both DLLs should be present
    // (second call rebuilds the section with the previous IDT entries + new)
    coffi c2;
    BOOST_REQUIRE(round_trip(c, c2));

    import_section_accessor imports2(c2);
    BOOST_CHECK_EQUAL(imports2.get_import_count(), 2u);

    // Check both DLLs (order should match insertion order)
    BOOST_CHECK_EQUAL(imports2.get_dll_name(0), "kernel32.dll");
    BOOST_CHECK_EQUAL(imports2.get_dll_name(1), "user32.dll");

    std::string name;
    uint16_t    hint;
    BOOST_CHECK_EQUAL(imports2.get_symbol(0, 0, name, hint), true);
    BOOST_CHECK_EQUAL(name, "ExitProcess");
    BOOST_CHECK_EQUAL(imports2.get_symbol(1, 0, name, hint), true);
    BOOST_CHECK_EQUAL(name, "MessageBoxA");
}

//------------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(add_multiple_symbols_same_dll)
{
    coffi c;
    init_minimal_pe(c, OH_MAGIC_PE32);

    import_section_accessor imports(c);

    std::vector<std::pair<std::string, uint16_t>> syms = {
        {"ExitProcess", 0x5E},
        {"LoadLibraryA", 0x100},
        {"GetProcAddress", 0x80},
    };
    BOOST_CHECK_EQUAL(imports.add_import("kernel32.dll", syms), true);

    coffi c2;
    BOOST_REQUIRE(round_trip(c, c2));

    import_section_accessor imports2(c2);
    BOOST_CHECK_EQUAL(imports2.get_import_count(), 1u);
    BOOST_CHECK_EQUAL(imports2.get_dll_name(0), "kernel32.dll");
    BOOST_CHECK_EQUAL(imports2.get_symbol_count(0), 3u);

    std::string name;
    uint16_t    hint;
    BOOST_CHECK_EQUAL(imports2.get_symbol(0, 0, name, hint), true);
    BOOST_CHECK_EQUAL(name, "ExitProcess");
    BOOST_CHECK_EQUAL(hint, 0x5E);

    BOOST_CHECK_EQUAL(imports2.get_symbol(0, 1, name, hint), true);
    BOOST_CHECK_EQUAL(name, "LoadLibraryA");
    BOOST_CHECK_EQUAL(hint, 0x100);

    BOOST_CHECK_EQUAL(imports2.get_symbol(0, 2, name, hint), true);
    BOOST_CHECK_EQUAL(name, "GetProcAddress");
    BOOST_CHECK_EQUAL(hint, 0x80);
}

//------------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(add_import_preserves_existing)
{
    coffi c;
    BOOST_REQUIRE_EQUAL(c.load("data/espui.dll"), true);

    import_section_accessor imports(c);
    uint32_t original_count = imports.get_import_count();
    BOOST_REQUIRE_GT(original_count, 0u);

    // Remember original DLL names
    std::vector<std::string> original_dlls;
    for (uint32_t i = 0; i < original_count; ++i) {
        original_dlls.push_back(imports.get_dll_name(i));
    }

    // Add a new import
    BOOST_CHECK_EQUAL(
        imports.add_import("vmpilot_runtime.dll", "vm_stub_entry"), true);

    // Save and reload
    coffi c2;
    BOOST_REQUIRE(round_trip(c, c2));

    import_section_accessor imports2(c2);
    BOOST_CHECK_EQUAL(imports2.get_import_count(), original_count + 1);

    // Verify all original imports are preserved
    for (uint32_t i = 0; i < original_count; ++i) {
        BOOST_CHECK_EQUAL(imports2.get_dll_name(i), original_dlls[i]);
    }

    // Verify the new import is at the end
    BOOST_CHECK_EQUAL(imports2.get_dll_name(original_count),
                      "vmpilot_runtime.dll");
}

//------------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(add_import_invalid_args)
{
    coffi c;
    init_minimal_pe(c, OH_MAGIC_PE32);

    import_section_accessor imports(c);

    // Empty DLL name
    BOOST_CHECK_EQUAL(imports.add_import("", "func"), false);

    // Empty symbols
    BOOST_CHECK_EQUAL(
        imports.add_import(
            "test.dll",
            std::vector<std::pair<std::string, uint16_t>>{}),
        false);

    // Should still have no imports
    BOOST_CHECK_EQUAL(imports.get_import_count(), 0u);
}

//------------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(add_import_corrupt_rva_no_crash)
{
    coffi c;
    init_minimal_pe(c, OH_MAGIC_PE32);

    // Manually set a bogus import directory RVA
    auto& dirs = c.get_directories();
    dirs[DIRECTORY_IMPORT_TABLE]->set_virtual_address(0xDEADBEEF);
    dirs[DIRECTORY_IMPORT_TABLE]->set_size(100);

    // Parsing should not crash — just return 0 imports
    import_section_accessor imports(c);
    BOOST_CHECK_EQUAL(imports.get_import_count(), 0u);
}

//------------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(add_import_data_directory_updated)
{
    coffi c;
    init_minimal_pe(c, OH_MAGIC_PE32);

    import_section_accessor imports(c);
    BOOST_CHECK_EQUAL(imports.add_import("test.dll", "func"), true);

    auto& dirs = c.get_directories();

    // DIRECTORY_IMPORT_TABLE should now be set
    BOOST_CHECK_NE(dirs[DIRECTORY_IMPORT_TABLE]->get_virtual_address(), 0u);
    BOOST_CHECK_NE(dirs[DIRECTORY_IMPORT_TABLE]->get_size(), 0u);

    // Size should be 2 entries * 20 bytes (1 real + 1 terminator)
    BOOST_CHECK_EQUAL(dirs[DIRECTORY_IMPORT_TABLE]->get_size(),
                      2u * sizeof(image_import_descriptor));

    // DIRECTORY_IAT should also be set
    BOOST_CHECK_NE(dirs[DIRECTORY_IAT]->get_virtual_address(), 0u);
    BOOST_CHECK_NE(dirs[DIRECTORY_IAT]->get_size(), 0u);
}

//------------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(pe32_vs_pe32plus_thunk_size)
{
    // Create PE32 with one import
    coffi c32;
    init_minimal_pe(c32, OH_MAGIC_PE32);
    {
        import_section_accessor imp(c32);
        imp.add_import("test.dll", "func");
    }

    // Create PE32+ with the same import
    coffi c64;
    init_minimal_pe(c64, OH_MAGIC_PE32PLUS);
    {
        import_section_accessor imp(c64);
        imp.add_import("test.dll", "func");
    }

    // Round-trip both to ensure sections are properly saved/loaded
    coffi c32r, c64r;
    BOOST_REQUIRE(round_trip(c32, c32r));
    BOOST_REQUIRE(round_trip(c64, c64r));

    // The PE32+ .idata section should be larger because thunks are 8 bytes
    // instead of 4.
    section* idata32 = c32r.get_sections()[".idata"];
    section* idata64 = c64r.get_sections()[".idata"];
    BOOST_REQUIRE_NE(idata32, (section*)0);
    BOOST_REQUIRE_NE(idata64, (section*)0);

    uint32_t size32 = idata32->get_data_size();
    uint32_t size64 = idata64->get_data_size();
    BOOST_CHECK_GT(size64, size32);

    // ILT: 2 entries (entry + null) * (8-4) = 8
    // IAT: 2 entries (entry + null) * (8-4) = 8
    // Total difference: 16 bytes
    BOOST_CHECK_EQUAL(size64 - size32, 16u);
}

//==============================================================================
// NEW: Tests added after code review
//==============================================================================

//------------------------------------------------------------------------------
// VMPilot exact workflow on real PE32+ binary
BOOST_AUTO_TEST_CASE(vmpilot_workflow_real_pe32plus)
{
    coffi c;
    BOOST_REQUIRE_EQUAL(c.load("data/notepad.exe"), true);

    import_section_accessor imports(c);
    uint32_t orig_count = imports.get_import_count();
    BOOST_REQUIRE_GT(orig_count, 0u);

    // Record original first DLL and its first symbol
    std::string orig_dll0 = imports.get_dll_name(0);
    uint32_t orig_sym_count0 = imports.get_symbol_count(0);
    std::string orig_sym0;
    uint16_t orig_hint0;
    BOOST_REQUIRE(imports.get_symbol(0, 0, orig_sym0, orig_hint0));

    // The VMPilot add
    BOOST_CHECK_EQUAL(
        imports.add_import("vmpilot_runtime.dll", "vm_stub_entry"), true);

    // Round-trip
    coffi c2;
    BOOST_REQUIRE(round_trip(c, c2));

    import_section_accessor imp2(c2);
    BOOST_CHECK_EQUAL(imp2.get_import_count(), orig_count + 1);

    // Existing imports survived (both DLL names AND symbols)
    BOOST_CHECK_EQUAL(imp2.get_dll_name(0), orig_dll0);
    BOOST_CHECK_EQUAL(imp2.get_symbol_count(0), orig_sym_count0);
    std::string sname;
    uint16_t shint;
    BOOST_CHECK_EQUAL(imp2.get_symbol(0, 0, sname, shint), true);
    BOOST_CHECK_EQUAL(sname, orig_sym0);

    // New import is present
    BOOST_CHECK_EQUAL(imp2.get_dll_name(orig_count), "vmpilot_runtime.dll");
    BOOST_CHECK_EQUAL(imp2.get_symbol_count(orig_count), 1u);
    BOOST_CHECK_EQUAL(imp2.get_symbol(orig_count, 0, sname, shint), true);
    BOOST_CHECK_EQUAL(sname, "vm_stub_entry");
}

//------------------------------------------------------------------------------
// Preserve existing: verify SYMBOLS not just DLL names
BOOST_AUTO_TEST_CASE(add_import_preserves_existing_symbols)
{
    coffi c;
    BOOST_REQUIRE_EQUAL(c.load("data/espui.dll"), true);

    import_section_accessor imports(c);
    uint32_t original_count = imports.get_import_count();
    BOOST_REQUIRE_GT(original_count, 0u);

    // Record original DLL names, symbol counts, and first symbol per DLL
    struct orig_info {
        std::string dll;
        uint32_t sym_count;
        std::string first_sym;
    };
    std::vector<orig_info> originals;
    for (uint32_t i = 0; i < original_count; ++i) {
        orig_info info;
        info.dll = imports.get_dll_name(i);
        info.sym_count = imports.get_symbol_count(i);
        std::string sn;
        uint16_t sh;
        if (imports.get_symbol(i, 0, sn, sh))
            info.first_sym = sn;
        originals.push_back(info);
    }

    BOOST_CHECK_EQUAL(
        imports.add_import("new_runtime.dll", "new_func"), true);

    coffi c2;
    BOOST_REQUIRE(round_trip(c, c2));

    import_section_accessor imp2(c2);
    for (uint32_t i = 0; i < original_count; ++i) {
        BOOST_CHECK_EQUAL(imp2.get_dll_name(i), originals[i].dll);
        BOOST_CHECK_EQUAL(imp2.get_symbol_count(i), originals[i].sym_count);
        if (!originals[i].first_sym.empty()) {
            std::string sn;
            uint16_t sh;
            BOOST_CHECK_EQUAL(imp2.get_symbol(i, 0, sn, sh), true);
            BOOST_CHECK_EQUAL(sn, originals[i].first_sym);
        }
    }
}

//------------------------------------------------------------------------------
// Multi-symbol on PE32+
BOOST_AUTO_TEST_CASE(add_multiple_symbols_same_dll_pe32plus)
{
    coffi c;
    init_minimal_pe(c, OH_MAGIC_PE32PLUS);

    import_section_accessor imports(c);
    std::vector<std::pair<std::string, uint16_t>> syms = {
        {"ExitProcess", 0x5E},
        {"LoadLibraryA", 0x100},
        {"GetProcAddress", 0x80},
    };
    BOOST_CHECK_EQUAL(imports.add_import("kernel32.dll", syms), true);

    coffi c2;
    BOOST_REQUIRE(round_trip(c, c2));

    import_section_accessor imp2(c2);
    BOOST_CHECK_EQUAL(imp2.get_import_count(), 1u);
    BOOST_CHECK_EQUAL(imp2.get_symbol_count(0), 3u);

    std::string name;
    uint16_t hint;
    BOOST_CHECK_EQUAL(imp2.get_symbol(0, 0, name, hint), true);
    BOOST_CHECK_EQUAL(name, "ExitProcess");
    BOOST_CHECK_EQUAL(hint, 0x5E);
    BOOST_CHECK_EQUAL(imp2.get_symbol(0, 1, name, hint), true);
    BOOST_CHECK_EQUAL(name, "LoadLibraryA");
    BOOST_CHECK_EQUAL(hint, 0x100);
    BOOST_CHECK_EQUAL(imp2.get_symbol(0, 2, name, hint), true);
    BOOST_CHECK_EQUAL(name, "GetProcAddress");
    BOOST_CHECK_EQUAL(hint, 0x80);
}

//------------------------------------------------------------------------------
// Consecutive adds on PE32+
BOOST_AUTO_TEST_CASE(add_multiple_imports_different_dlls_pe32plus)
{
    coffi c;
    init_minimal_pe(c, OH_MAGIC_PE32PLUS);

    import_section_accessor imports(c);
    BOOST_CHECK_EQUAL(imports.add_import("kernel32.dll", "ExitProcess"), true);
    BOOST_CHECK_EQUAL(imports.add_import("user32.dll", "MessageBoxA"), true);

    coffi c2;
    BOOST_REQUIRE(round_trip(c, c2));

    import_section_accessor imp2(c2);
    BOOST_CHECK_EQUAL(imp2.get_import_count(), 2u);

    std::string name;
    uint16_t hint;
    BOOST_CHECK_EQUAL(imp2.get_symbol(0, 0, name, hint), true);
    BOOST_CHECK_EQUAL(name, "ExitProcess");
    BOOST_CHECK_EQUAL(imp2.get_symbol(1, 0, name, hint), true);
    BOOST_CHECK_EQUAL(name, "MessageBoxA");
}

//------------------------------------------------------------------------------
// Three consecutive add_import calls
BOOST_AUTO_TEST_CASE(add_three_imports_consecutively)
{
    coffi c;
    init_minimal_pe(c, OH_MAGIC_PE32);

    import_section_accessor imports(c);
    BOOST_CHECK_EQUAL(imports.add_import("a.dll", "funcA"), true);
    BOOST_CHECK_EQUAL(imports.add_import("b.dll", "funcB"), true);
    BOOST_CHECK_EQUAL(imports.add_import("c.dll", "funcC"), true);

    coffi c2;
    BOOST_REQUIRE(round_trip(c, c2));

    import_section_accessor imp2(c2);
    BOOST_CHECK_EQUAL(imp2.get_import_count(), 3u);

    std::string name;
    uint16_t hint;
    BOOST_CHECK_EQUAL(imp2.get_dll_name(0), "a.dll");
    BOOST_CHECK_EQUAL(imp2.get_symbol(0, 0, name, hint), true);
    BOOST_CHECK_EQUAL(name, "funcA");
    BOOST_CHECK_EQUAL(imp2.get_dll_name(1), "b.dll");
    BOOST_CHECK_EQUAL(imp2.get_symbol(1, 0, name, hint), true);
    BOOST_CHECK_EQUAL(name, "funcB");
    BOOST_CHECK_EQUAL(imp2.get_dll_name(2), "c.dll");
    BOOST_CHECK_EQUAL(imp2.get_symbol(2, 0, name, hint), true);
    BOOST_CHECK_EQUAL(name, "funcC");
}

//------------------------------------------------------------------------------
// Long DLL name and symbol name
BOOST_AUTO_TEST_CASE(add_import_long_names)
{
    coffi c;
    init_minimal_pe(c, OH_MAGIC_PE32);

    import_section_accessor imports(c);
    std::string long_dll(260, 'A');
    long_dll += ".dll";
    std::string long_sym(512, 'B');

    BOOST_CHECK_EQUAL(imports.add_import(long_dll, long_sym), true);

    coffi c2;
    BOOST_REQUIRE(round_trip(c, c2));

    import_section_accessor imp2(c2);
    BOOST_CHECK_EQUAL(imp2.get_dll_name(0), long_dll);
    std::string name;
    uint16_t hint;
    BOOST_CHECK_EQUAL(imp2.get_symbol(0, 0, name, hint), true);
    BOOST_CHECK_EQUAL(name, long_sym);
}

//------------------------------------------------------------------------------
// Stress: 1 DLL with 100 symbols
BOOST_AUTO_TEST_CASE(add_import_many_symbols)
{
    coffi c;
    init_minimal_pe(c, OH_MAGIC_PE32);

    import_section_accessor imports(c);
    std::vector<std::pair<std::string, uint16_t>> syms;
    for (int i = 0; i < 100; ++i) {
        syms.push_back({"func_" + std::to_string(i),
                         static_cast<uint16_t>(i)});
    }
    BOOST_CHECK_EQUAL(imports.add_import("big.dll", syms), true);

    coffi c2;
    BOOST_REQUIRE(round_trip(c, c2));

    import_section_accessor imp2(c2);
    BOOST_CHECK_EQUAL(imp2.get_symbol_count(0), 100u);

    std::string name;
    uint16_t hint;
    BOOST_CHECK_EQUAL(imp2.get_symbol(0, 0, name, hint), true);
    BOOST_CHECK_EQUAL(name, "func_0");
    BOOST_CHECK_EQUAL(hint, 0u);
    BOOST_CHECK_EQUAL(imp2.get_symbol(0, 99, name, hint), true);
    BOOST_CHECK_EQUAL(name, "func_99");
    BOOST_CHECK_EQUAL(hint, 99u);
}

//------------------------------------------------------------------------------
// No optional header — add_import should return false, not crash
BOOST_AUTO_TEST_CASE(add_import_no_optional_header)
{
    coffi c;
    c.create(COFFI_ARCHITECTURE_PE);
    // Do NOT call create_optional_header

    import_section_accessor imports(c);
    BOOST_CHECK_EQUAL(imports.add_import("test.dll", "func"), false);
}

//------------------------------------------------------------------------------
// Corrupted PE files should not crash the parser
BOOST_AUTO_TEST_CASE(read_imports_corrupted_files_no_crash)
{
    const char* files[] = {
        "data/notepad-corrupted1.exe",
        "data/notepad-corrupted2.exe",
        "data/notepad-corrupted3.exe",
        "data/notepad-corrupted4.exe",
    };
    for (const char* f : files) {
        coffi c;
        if (c.load(f)) {
            import_section_accessor imports(c);
            // Must not crash regardless of content
            (void)imports.get_import_count();
            (void)imports.get_dll_name(0);
            (void)imports.get_symbol_count(0);
        }
    }
}

//------------------------------------------------------------------------------
// Ordinal imports: verify is_ordinal field via get_imports()
BOOST_AUTO_TEST_CASE(read_imports_ordinal_fields)
{
    coffi c;
    BOOST_REQUIRE_EQUAL(c.load("data/notepad.exe"), true);

    import_section_accessor imports(c);
    const auto& mods = imports.get_imports();
    BOOST_REQUIRE_GT(mods.size(), 0u);

    // Verify that name-based imports have non-empty names and !is_ordinal
    for (const auto& mod : mods) {
        for (const auto& sym : mod.symbols) {
            if (!sym.is_ordinal) {
                BOOST_CHECK(!sym.name.empty());
            }
        }
    }
}

//------------------------------------------------------------------------------
// Verify hint values survive round-trip in single-import case
BOOST_AUTO_TEST_CASE(add_single_import_hint_preserved)
{
    coffi c;
    init_minimal_pe(c, OH_MAGIC_PE32);

    import_section_accessor imports(c);
    BOOST_CHECK_EQUAL(imports.add_import("test.dll", "func", 0x42), true);

    coffi c2;
    BOOST_REQUIRE(round_trip(c, c2));

    import_section_accessor imp2(c2);
    std::string name;
    uint16_t hint;
    BOOST_CHECK_EQUAL(imp2.get_symbol(0, 0, name, hint), true);
    BOOST_CHECK_EQUAL(name, "func");
    BOOST_CHECK_EQUAL(hint, 0x42);
}

//------------------------------------------------------------------------------
// Read known DLL from notepad.exe to verify non-garbage parsing
BOOST_AUTO_TEST_CASE(read_imports_known_dll)
{
    coffi c;
    BOOST_REQUIRE_EQUAL(c.load("data/notepad.exe"), true);

    import_section_accessor imports(c);
    const auto& mods = imports.get_imports();

    bool found_known = false;
    for (const auto& mod : mods) {
        // notepad.exe should import from at least one well-known DLL
        if (mod.dll_name.find("KERNEL32") != std::string::npos ||
            mod.dll_name.find("kernel32") != std::string::npos ||
            mod.dll_name.find("ntdll") != std::string::npos ||
            mod.dll_name.find("NTDLL") != std::string::npos ||
            mod.dll_name.find("msvcrt") != std::string::npos ||
            mod.dll_name.find("api-ms-") != std::string::npos) {
            found_known = true;
            break;
        }
    }
    BOOST_CHECK(found_known);
}
