# Migration Guide: COFFI to coffi-modern

This document covers every API change when migrating from the original COFFI library to coffi-modern.

## Key Architectural Changes

| Aspect | COFFI (original) | coffi-modern |
|--------|-----------------|-------------|
| Polymorphism | `virtual` functions, runtime dispatch | Template traits (`coff_file<pe32_traits>`), zero virtual functions |
| Read/Write split | Single `coffi` class does both | `coff_file<T>` (read-only, zero-copy) + `coff_editor<T>` (mutable, owned) |
| Memory model | Eager allocation (`unique_ptr<char[]>`) | Zero-copy `byte_view` (read) / `std::vector` (write) |
| Error handling | `bool` returns | `result<T, error_code>` with monadic `.map()` / `.and_then()` |
| Iteration | `std::vector` + index | Lazy ranges + pipe `\|` syntax (`filter`, `transform`, `take_while`) |
| String returns | `std::string` (copies) | `std::string_view` (zero-copy, read path) |
| Header-only | No (needs compilation) | Yes |
| Exceptions | Mixed | None (`result<T, E>` everywhere) |

## Include Change

```cpp
// Old
#include <coffi/coffi.hpp>

// New (single include, same path)
#include <coffi/coffi.hpp>
```

## 1. Loading Files

### Read-only (analysis, inspection)

```cpp
// ---- Old ----
COFFI::coffi reader;
if (!reader.load("app.exe")) { /* failed, no reason */ }

// ---- New ----
auto buf = coffi::file_buffer::from_file("app.exe");
if (!buf) { std::cerr << coffi::to_string(buf.error()); return; }

// Explicit architecture:
auto file = coffi::coff_file<coffi::pe32plus_traits>::from_view(buf->view());
if (!file) { std::cerr << coffi::to_string(file.error()); return; }

// Or auto-detect:
auto file = coffi::auto_load(buf->view());  // returns variant<pe32, pe32plus>
std::visit([](auto& f) { /* use f */ }, *file);
```

### Read-write (editing, saving)

```cpp
// ---- Old ----
COFFI::coffi editor;
editor.load("app.exe");
// ... modify ...
editor.save("app_modified.exe");

// ---- New ----
auto ed = coffi::coff_editor<coffi::pe32_traits>::from_path("app.exe");
if (!ed) { /* handle error */ }
// ... modify ...
auto r = ed->save("app_modified.exe");
if (!r) { /* handle error */ }
```

### Create from scratch

```cpp
// ---- Old ----
COFFI::coffi writer;
writer.create(COFFI_ARCHITECTURE_PE);
writer.create_optional_header();

// ---- New ----
coffi::coff_editor<coffi::pe32_traits> ed;
ed.create_dos_header();
ed.create_optional_header();
ed.create_win_header();
ed.ensure_directories(16);
ed.coff_header().machine = coffi::MACHINE_I386;
```

## 2. Error Handling

```cpp
// ---- Old ----
if (!reader.load("file.exe")) {
    // No way to know WHY it failed
}

// ---- New ----
auto file = coffi::coff_file<coffi::pe32_traits>::from_view(data);
if (!file) {
    // Exact reason:
    std::cerr << coffi::to_string(file.error()) << "\n";
    // e.g. "invalid PE signature", "truncated header", "file too small"
}

// Monadic chaining:
auto entry = file->optional_header()
    .map([](auto h) { return h.entry_point_address; });
// entry is result<uint32_t> — either value or error, no if-checking needed

// value_or:
uint32_t ep = file->optional_header()
    .map([](auto h) { return h.entry_point_address; })
    .value_or(0);
```

## 3. Header Access

```cpp
// ---- Old ----
auto* dos  = reader.get_msdos_header();   // returns pointer, may be null
auto* hdr  = reader.get_header();         // coff_header*
auto* opt  = reader.get_optional_header(); // optional_header*
auto* win  = reader.get_win_header();     // win_header*
uint16_t machine = hdr->get_machine();
uint32_t ep = opt->get_entry_point_address();

// ---- New (read-only) ----
auto dos = file->dos_header();    // result<msdos_header>  (by value)
auto hdr = file->coff_header();   // result<coff_file_header>
auto opt = file->optional_header(); // result<Traits::optional_header_type>
auto win = file->win_header();    // result<Traits::win_header_type>
uint16_t machine = hdr->machine;  // direct struct field access
uint32_t ep = opt->entry_point_address;

// ---- New (mutable) ----
ed.coff_header().machine = coffi::MACHINE_AMD64;  // direct assignment
ed.optional_header()->entry_point_address = 0x1000;
```

Note: Read path returns copies (via `result<T>`), not pointers. This is by design for zero-copy safety. Editor returns mutable pointers/references.

## 4. Section Operations

### Iteration

```cpp
// ---- Old ----
for (int i = 0; i < reader.get_sections().size(); ++i) {
    auto* sec = reader.get_sections()[i];
    std::string name = sec->get_name();        // allocates
    const char* data = sec->get_data();
    uint32_t size = sec->get_data_size();
}

// ---- New (zero-copy, lazy) ----
for (auto sec : file->sections()) {
    std::string_view name = sec.name();        // zero-copy
    coffi::byte_view data = sec.data();        // zero-copy
    uint32_t size = sec.data_size();
}
```

### Find by name

```cpp
// ---- Old ----
auto* sec = reader.get_sections()[".text"];

// ---- New (read path) ----
auto sec = coffi::find_first(file->sections(),
    [](auto s) { return s.name() == ".text"; });
if (sec) { /* use *sec */ }

// ---- New (editor) ----
auto* sec = ed.find_section(".text");
if (sec) { /* use sec-> */ }
```

### Filter with pipe syntax (new feature)

```cpp
// Find all executable sections:
auto code = file->sections()
    | coffi::filter([](auto s) { return s.is_executable(); });

// Get names of all data sections:
auto names = file->sections()
    | coffi::filter([](auto s) { return s.is_data(); })
    | coffi::transform([](auto s) { return s.name(); });

for (auto name : names) std::cout << name << "\n";
```

### Section CRUD (editor)

```cpp
// ---- Old ----
auto* sec = writer.add_section(".text");
sec->set_data(code_ptr, code_size);
sec->set_flags(IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE);
sec->append_data(more_data, more_size);

// ---- New ----
auto& sec = ed.add_section(".text", coffi::SCN_CNT_CODE | coffi::SCN_MEM_READ | coffi::SCN_MEM_EXECUTE);
sec.set_data(code_ptr, code_size);
sec.set_virtual_address(0x1000);
sec.set_virtual_size(code_size);
sec.append_data(more_data, more_size);

// Remove:
ed.remove_section(".text");  // by name
ed.remove_section(0);        // by index
```

### Relocations

```cpp
// ---- Old ----
auto& relocs = sec->get_relocations();
for (auto& r : relocs) { /* r.get_virtual_address(), etc. */ }
sec->add_relocation_entry(&entry);

// ---- New (read) ----
for (uint32_t i = 0; i < sec.reloc_count(); ++i) {
    auto r = sec.relocation(i);  // result<rel_entry>
    if (r) { /* r->virtual_address, r->symbol_table_index, r->type */ }
}

// ---- New (editor) ----
for (auto& r : sec.relocations()) { /* direct vector access */ }
sec.add_relocation(entry);
```

### Line Numbers

```cpp
// ---- Old ----
// Accessed via get_line_num_count(), get_line_num_offset()

// ---- New (read) ----
for (uint32_t i = 0; i < sec.line_num_count(); ++i) {
    auto ln = sec.line_number(i);  // result<line_number_entry>
}

// ---- New (editor) ----
sec.add_line_number(entry);
for (auto& ln : sec.line_numbers()) { /* direct access */ }
```

## 5. Symbol Operations

### Iteration

```cpp
// ---- Old ----
auto* syms = reader.get_symbols();
for (auto& sym : *syms) {
    std::string name = sym.get_name();         // allocates
    uint32_t val = sym.get_value();
    auto& auxs = sym.get_auxiliary_symbols();
}

// ---- New (zero-copy, auto-skips aux records) ----
for (auto sym : file->symbols()) {
    std::string_view name = sym.name();        // zero-copy
    uint32_t val = sym.value();
    uint8_t aux_count = sym.aux_count();
}
```

### Find & lookup

```cpp
// ---- Old ----
auto* sym = reader.get_symbol("_main");       // by name
auto* sym = reader.get_symbol(42);            // by raw index

// ---- New (editor) ----
auto* sym = ed.find_symbol("_main");          // by name
```

### CRUD (editor)

```cpp
// ---- Old ----
auto* sym = writer.add_symbol("_main");
sym->set_value(0x1000);
sym->set_section_number(1);
sym->set_storage_class(2);

// ---- New ----
auto& sym = ed.add_symbol("_main");
sym.set_value(0x1000);
sym.set_section_number(1);
sym.set_storage_class(2);

// Auxiliary records:
coffi::auxiliary_symbol_record aux{};
sym.add_aux(aux);

// Remove:
ed.remove_symbol(0);  // by index
```

## 6. Import Table

### Reading

```cpp
// ---- Old ----
COFFI::import_section_accessor imp(reader);
for (uint32_t i = 0; i < imp.get_import_count(); ++i) {
    std::string dll = imp.get_dll_name(i);
    for (uint32_t j = 0; j < imp.get_symbol_count(i); ++j) {
        std::string name; uint16_t hint;
        imp.get_symbol(i, j, name, hint);
    }
}

// ---- New (lazy, nested ranges) ----
for (auto mod : file->imports()) {
    std::string_view dll = mod.dll_name();     // zero-copy
    for (auto sym : mod.symbols()) {
        if (sym.is_ordinal()) {
            uint16_t ord = sym.ordinal();
        } else {
            std::string_view name = sym.name(); // zero-copy
            uint16_t hint = sym.hint();
        }
    }
}
```

### Writing

```cpp
// ---- Old ----
COFFI::import_section_accessor imp(writer);
imp.add_import("kernel32.dll", {{"LoadLibraryA", 0}, {"GetProcAddress", 0}});

// ---- New (lazy builder, materialized during save) ----
ed.imports().add_module("kernel32.dll", {
    {"LoadLibraryA", 0},
    {"GetProcAddress", 0}
});
// Or one at a time:
ed.imports().add_symbol("kernel32.dll", "ExitProcess", 0);
```

## 7. Data Directories

```cpp
// ---- Old ----
auto& dirs = reader.get_directories();
auto* dir = dirs[DIRECTORY_IMPORT_TABLE];
uint32_t rva = dir->get_virtual_address();

// ---- New (read) ----
auto dir = file->data_directory(coffi::DIR_IMPORT);  // result<image_data_directory>
if (dir) {
    uint32_t rva = dir->virtual_address;  // direct struct field
}

// ---- New (editor) ----
ed.ensure_directories(16);
ed.set_directory(coffi::DIR_IMPORT, {0x2000, 100});
auto* d = ed.directory(coffi::DIR_IMPORT);  // returns pointer
```

## 8. DOS Stub

```cpp
// ---- Old ----
const char* stub = reader.get_msdos_header()->get_stub();
uint32_t stub_size = reader.get_msdos_header()->get_stub_size();

// ---- New (editor) ----
const auto& stub = ed.dos_stub();  // const vector<char>&
ed.set_dos_stub(data, size);
ed.clear_dos_stub();
```

## 9. Architecture Detection

```cpp
// ---- Old ----
COFFI::coffi reader;
reader.load("file.exe");
auto arch = reader.get_architecture();
if (arch == COFFI_ARCHITECTURE_PE) { ... }
if (reader.is_PE32_plus()) { ... }

// ---- New ----
auto buf = coffi::file_buffer::from_file("file.exe");
auto arch = coffi::detect_architecture(buf->view());
switch (*arch) {
    case coffi::detected_arch::pe32:     /* 32-bit PE */     break;
    case coffi::detected_arch::pe32plus: /* 64-bit PE */     break;
    case coffi::detected_arch::ti:       /* TI COFF */       break;
    case coffi::detected_arch::ceva:     /* CEVA COFF */     break;
    case coffi::detected_arch::unknown:  /* unknown format */ break;
}
```

## 10. String Table

```cpp
// ---- Old ----
std::string name = reader.string_to_name(raw_name_field);
std::string_view sv = reader.string_to_name_view(raw_name_field);

// ---- New (read) ----
auto sv = file->strings().resolve_name(raw_name_field);

// ---- New (editor) ----
// String table is auto-managed during save().
// Long names (>8 chars) are automatically encoded.
// You can also manually add entries:
uint32_t offset = ed.string_table().add("long_symbol_name");
```

## 11. Saving Files

```cpp
// ---- Old ----
writer.layout();      // optional manual layout
writer.save("output.exe");

// ---- New ----
// layout() is called automatically by save()
auto buf = ed.save();                  // result<vector<char>>
auto r   = ed.save("output.exe");     // result<void>

// PE checksum is computed automatically during save().
```

## 12. Constant Name Changes

| COFFI | coffi-modern |
|-------|-------------|
| `IMAGE_SCN_CNT_CODE` | `coffi::SCN_CNT_CODE` |
| `IMAGE_SCN_CNT_INITIALIZED_DATA` | `coffi::SCN_CNT_INITIALIZED_DATA` |
| `IMAGE_SCN_MEM_READ` | `coffi::SCN_MEM_READ` |
| `IMAGE_SCN_MEM_WRITE` | `coffi::SCN_MEM_WRITE` |
| `IMAGE_SCN_MEM_EXECUTE` | `coffi::SCN_MEM_EXECUTE` |
| `IMAGE_FILE_MACHINE_I386` | `coffi::MACHINE_I386` |
| `IMAGE_FILE_MACHINE_AMD64` | `coffi::MACHINE_AMD64` |
| `OH_MAGIC_PE32` | `coffi::OH_MAGIC_PE32` |
| `OH_MAGIC_PE32PLUS` | `coffi::OH_MAGIC_PE32PLUS` |
| `DIRECTORY_IMPORT_TABLE` | `coffi::DIR_IMPORT` |
| `DIRECTORY_IAT` | `coffi::DIR_IAT` |
| `COFFI_ARCHITECTURE_PE` | `coffi::detected_arch::pe32` |
| `COFFI_ARCHITECTURE_TI` | `coffi::detected_arch::ti` |

## 13. Complete Example: Read-Modify-Write

```cpp
#include <coffi/coffi.hpp>
#include <iostream>

int main() {
    // Load existing PE into editor
    auto ed = coffi::coff_editor<coffi::pe32_traits>::from_path("input.exe");
    if (!ed) {
        std::cerr << coffi::to_string(ed.error()) << "\n";
        return 1;
    }

    // Add a new section
    auto& sec = ed->add_section(".mydata",
        coffi::SCN_CNT_INITIALIZED_DATA | coffi::SCN_MEM_READ);
    sec.set_data("Hello from coffi-modern!", 24);
    sec.set_virtual_address(0x5000);
    sec.set_virtual_size(24);

    // Add a symbol
    auto& sym = ed->add_symbol("_my_data");
    sym.set_value(0x5000);
    sym.set_section_number(static_cast<uint16_t>(ed->section_count()));

    // Save
    auto r = ed->save("output.exe");
    if (!r) {
        std::cerr << coffi::to_string(r.error()) << "\n";
        return 1;
    }

    std::cout << "Saved successfully\n";
}
```
