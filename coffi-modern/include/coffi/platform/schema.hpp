#pragma once

/// Raw binary structure definitions for PE / COFF formats.
/// All structs are packed (#pragma pack(1)) to match on-disk layout exactly.
/// Fields use raw integer types; endian conversion happens at the view layer.

#include <cstdint>
#include <cstddef>

namespace coffi {

#pragma pack(push, 1)

// ================================================================
//  Constants
// ================================================================

// DOS / PE magic bytes
inline constexpr uint8_t  PEMAG0 = 'M';  // 0x4D
inline constexpr uint8_t  PEMAG1 = 'Z';  // 0x5A
inline constexpr uint32_t PE_SIGNATURE = 0x00004550;  // "PE\0\0" little-endian

// Optional header magic
inline constexpr uint16_t OH_MAGIC_PE32     = 0x010B;
inline constexpr uint16_t OH_MAGIC_PE32ROM  = 0x0107;
inline constexpr uint16_t OH_MAGIC_PE32PLUS = 0x020B;

// Symbol name field size
inline constexpr std::size_t COFFI_NAME_SIZE = 8;

// Data directory indices
inline constexpr uint32_t DIR_EXPORT         = 0;
inline constexpr uint32_t DIR_IMPORT         = 1;
inline constexpr uint32_t DIR_RESOURCE       = 2;
inline constexpr uint32_t DIR_EXCEPTION      = 3;
inline constexpr uint32_t DIR_SECURITY       = 4;
inline constexpr uint32_t DIR_BASERELOC      = 5;
inline constexpr uint32_t DIR_DEBUG          = 6;
inline constexpr uint32_t DIR_ARCHITECTURE   = 7;
inline constexpr uint32_t DIR_GLOBALPTR      = 8;
inline constexpr uint32_t DIR_TLS            = 9;
inline constexpr uint32_t DIR_LOAD_CONFIG    = 10;
inline constexpr uint32_t DIR_BOUND_IMPORT   = 11;
inline constexpr uint32_t DIR_IAT            = 12;
inline constexpr uint32_t DIR_DELAY_IMPORT   = 13;
inline constexpr uint32_t DIR_CLR_RUNTIME    = 14;

// Section flags
inline constexpr uint32_t SCN_CNT_CODE                = 0x00000020;
inline constexpr uint32_t SCN_CNT_INITIALIZED_DATA    = 0x00000040;
inline constexpr uint32_t SCN_CNT_UNINITIALIZED_DATA  = 0x00000080;
inline constexpr uint32_t SCN_MEM_DISCARDABLE         = 0x02000000;
inline constexpr uint32_t SCN_MEM_SHARED              = 0x10000000;
inline constexpr uint32_t SCN_MEM_EXECUTE              = 0x20000000;
inline constexpr uint32_t SCN_MEM_READ                 = 0x40000000;
inline constexpr uint32_t SCN_MEM_WRITE                = 0x80000000;

// Machine types
inline constexpr uint16_t MACHINE_UNKNOWN   = 0x0000;
inline constexpr uint16_t MACHINE_I386      = 0x014C;
inline constexpr uint16_t MACHINE_AMD64     = 0x8664;
inline constexpr uint16_t MACHINE_ARM       = 0x01C0;
inline constexpr uint16_t MACHINE_ARMNT     = 0x01C4;
inline constexpr uint16_t MACHINE_ARM64     = 0xAA64;
inline constexpr uint16_t MACHINE_POWERPC   = 0x01F0;

// ================================================================
//  MS-DOS Header
// ================================================================

struct msdos_header {
    uint16_t signature;              // "MZ"
    uint16_t bytes_in_last_block;
    uint16_t blocks_in_file;
    uint16_t num_relocs;
    uint16_t header_paragraphs;
    uint16_t min_extra_paragraphs;
    uint16_t max_extra_paragraphs;
    uint16_t ss;
    uint16_t sp;
    uint16_t checksum;
    uint16_t ip;
    uint16_t cs;
    uint16_t reloc_table_offset;
    uint16_t overlay_number;
    uint16_t reserved1[4];
    uint16_t oem_id;
    uint16_t oem_info;
    uint16_t reserved2[10];
    int32_t  pe_sign_location;       // offset to PE signature
};
static_assert(sizeof(msdos_header) == 64, "msdos_header must be 64 bytes");

// ================================================================
//  COFF File Header
// ================================================================

struct coff_file_header {
    uint16_t machine;
    uint16_t sections_count;
    uint32_t time_date_stamp;
    uint32_t symbol_table_offset;
    uint32_t symbols_count;
    uint16_t optional_header_size;
    uint16_t flags;
};
static_assert(sizeof(coff_file_header) == 20, "coff_file_header must be 20 bytes");

// ================================================================
//  COFF Optional Headers (PE32 / PE32+)
// ================================================================

struct coff_optional_header_pe {
    uint16_t magic;                  // 0x10B
    uint8_t  major_linker_version;
    uint8_t  minor_linker_version;
    uint32_t code_size;
    uint32_t initialized_data_size;
    uint32_t uninitialized_data_size;
    uint32_t entry_point_address;
    uint32_t code_base;
    uint32_t data_base;              // PE32 only
};
static_assert(sizeof(coff_optional_header_pe) == 28);

struct coff_optional_header_pe_plus {
    uint16_t magic;                  // 0x20B
    uint8_t  major_linker_version;
    uint8_t  minor_linker_version;
    uint32_t code_size;
    uint32_t initialized_data_size;
    uint32_t uninitialized_data_size;
    uint32_t entry_point_address;
    uint32_t code_base;
    // Note: no data_base in PE32+
};
static_assert(sizeof(coff_optional_header_pe_plus) == 24);

// ================================================================
//  Windows NT Headers (follows optional header)
// ================================================================

struct win_header_pe {
    uint32_t image_base;
    uint32_t section_alignment;
    uint32_t file_alignment;
    uint16_t major_os_version;
    uint16_t minor_os_version;
    uint16_t major_image_version;
    uint16_t minor_image_version;
    uint16_t major_subsystem_version;
    uint16_t minor_subsystem_version;
    uint32_t win32_version_value;
    uint32_t image_size;
    uint32_t headers_size;
    uint32_t checksum;
    uint16_t subsystem;
    uint16_t dll_flags;
    uint32_t stack_reserve_size;
    uint32_t stack_commit_size;
    uint32_t heap_reserve_size;
    uint32_t heap_commit_size;
    uint32_t loader_flags;
    uint32_t number_of_rva_and_sizes;
};
static_assert(sizeof(win_header_pe) == 68, "win_header_pe size check");

struct win_header_pe_plus {
    uint64_t image_base;             // 64-bit
    uint32_t section_alignment;
    uint32_t file_alignment;
    uint16_t major_os_version;
    uint16_t minor_os_version;
    uint16_t major_image_version;
    uint16_t minor_image_version;
    uint16_t major_subsystem_version;
    uint16_t minor_subsystem_version;
    uint32_t win32_version_value;
    uint32_t image_size;
    uint32_t headers_size;
    uint32_t checksum;
    uint16_t subsystem;
    uint16_t dll_flags;
    uint64_t stack_reserve_size;     // 64-bit
    uint64_t stack_commit_size;      // 64-bit
    uint64_t heap_reserve_size;      // 64-bit
    uint64_t heap_commit_size;       // 64-bit
    uint32_t loader_flags;
    uint32_t number_of_rva_and_sizes;
};
static_assert(sizeof(win_header_pe_plus) == 88, "win_header_pe_plus size check");

// ================================================================
//  Data Directory Entry
// ================================================================

struct image_data_directory {
    uint32_t virtual_address;
    uint32_t size;
};
static_assert(sizeof(image_data_directory) == 8);

// ================================================================
//  Section Header
// ================================================================

struct section_header {
    char     name[8];
    uint32_t virtual_size;
    uint32_t virtual_address;
    uint32_t data_size;
    uint32_t data_offset;
    uint32_t reloc_offset;
    uint32_t line_num_offset;
    uint16_t reloc_count;
    uint16_t line_num_count;
    uint32_t flags;
};
static_assert(sizeof(section_header) == 40, "section_header must be 40 bytes");

// ================================================================
//  Symbol Records
// ================================================================

struct symbol_record {
    char     name[8];
    uint32_t value;
    uint16_t section_number;
    uint16_t type;
    uint8_t  storage_class;
    uint8_t  aux_symbols_number;
};
static_assert(sizeof(symbol_record) == 18, "symbol_record must be 18 bytes");

struct auxiliary_symbol_record {
    char value[18];
};
static_assert(sizeof(auxiliary_symbol_record) == 18);

// Aux format 5: section definition (COMDAT)
struct auxiliary_symbol_record_5 {
    uint32_t length;
    uint16_t number_of_relocations;
    uint16_t number_of_linenumbers;
    uint32_t check_sum;
    uint16_t number;
    uint8_t  selection;
    uint8_t  unused[3];
};
static_assert(sizeof(auxiliary_symbol_record_5) == 18);

// ================================================================
//  Relocation Entry
// ================================================================

struct rel_entry {
    uint32_t virtual_address;
    uint32_t symbol_table_index;
    uint16_t type;
};
static_assert(sizeof(rel_entry) == 10);

// ================================================================
//  Line Number Entry
// ================================================================

struct line_number_entry {
    uint32_t type;
    uint16_t line_no;
};
static_assert(sizeof(line_number_entry) == 6);

// ================================================================
//  Import Table Structures
// ================================================================

struct image_import_descriptor {
    uint32_t original_first_thunk;   // RVA to ILT
    uint32_t time_date_stamp;
    uint32_t forwarder_chain;
    uint32_t name;                   // RVA to DLL name
    uint32_t first_thunk;            // RVA to IAT
};
static_assert(sizeof(image_import_descriptor) == 20);

struct image_import_by_name {
    uint16_t hint;
    // followed by null-terminated function name
};
static_assert(sizeof(image_import_by_name) == 2);

// ================================================================
//  Texas Instruments COFF Structures
// ================================================================

// TI target IDs
inline constexpr uint16_t TI_TMS470          = 0x0097;
inline constexpr uint16_t TI_TMS320C5400     = 0x0098;
inline constexpr uint16_t TI_TMS320C6000     = 0x0099;
inline constexpr uint16_t TI_TMS320C5500     = 0x009C;
inline constexpr uint16_t TI_TMS320C2800     = 0x009D;
inline constexpr uint16_t TI_MSP430          = 0x00A0;
inline constexpr uint16_t TI_TMS320C5500PLUS = 0x00A1;

// TI section flags (STYP_*)
inline constexpr uint32_t STYP_REG    = 0x00000000;
inline constexpr uint32_t STYP_DSECT  = 0x00000001;
inline constexpr uint32_t STYP_NOLOAD = 0x00000002;
inline constexpr uint32_t STYP_TEXT   = 0x00000020;
inline constexpr uint32_t STYP_DATA   = 0x00000040;
inline constexpr uint32_t STYP_BSS    = 0x00000080;

struct coff_file_header_ti {
    uint16_t version;
    uint16_t sections_count;
    uint32_t time_date_stamp;
    uint32_t symbol_table_offset;
    uint32_t symbols_count;
    uint16_t optional_header_size;
    uint16_t flags;
    uint16_t target_id;
};
static_assert(sizeof(coff_file_header_ti) == 22);

struct section_header_ti {
    char     name[8];
    uint32_t physical_address;
    uint32_t virtual_address;
    uint32_t data_size;
    uint32_t data_offset;
    uint32_t reloc_offset;
    uint32_t reserved_0;
    uint32_t reloc_count;
    uint32_t line_num_count;
    uint32_t flags;
    uint16_t reserved_1;
    uint16_t page_number;
};
static_assert(sizeof(section_header_ti) == 48);

struct common_optional_header_ti {
    uint16_t magic;
    uint16_t linker_version;
    uint32_t code_size;
    uint32_t initialized_data_size;
    uint32_t uninitialized_data_size;
    uint32_t entry_point_address;
    uint32_t code_base;
    uint32_t data_base;
};
static_assert(sizeof(common_optional_header_ti) == 28);

struct rel_entry_ti {
    uint32_t virtual_address;
    uint32_t symbol_table_index;
    uint16_t reserved;
    uint16_t type;
};
static_assert(sizeof(rel_entry_ti) == 12);

// ================================================================
//  CEVA COFF Structures
// ================================================================

inline constexpr uint16_t CEVA_MACHINE_XC4210_LIB = 0xDCA6;
inline constexpr uint16_t CEVA_MACHINE_XC4210_OBJ = 0x8CA6;
inline constexpr uint32_t CEVA_UNINITIALIZED_DATA  = 0x80;

struct rel_entry_ceva {
    uint32_t virtual_address;
    uint32_t symbol_table_index;
    uint32_t type;  // 32-bit (not 16-bit like PE)
};
static_assert(sizeof(rel_entry_ceva) == 12);

#pragma pack(pop)

} // namespace coffi
