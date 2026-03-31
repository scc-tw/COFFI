# coffi-modern

Modern C++17 header-only COFF/PE parser built on template metaprogramming, zero-copy lazy evaluation, and no-exception error handling.

A complete rewrite of [COFFI](https://github.com/serge1/COFFI), replacing virtual functions with compile-time traits, eager allocation with lazy views, and exceptions with a monadic `result<T, E>` type.

## Features

- **Header-only** — just add `include/` to your include path
- **C++17, Standard Library only** — no Windows SDK, no Boost, no external dependencies
- **Zero-copy parsing** — `byte_view` operates directly on the file buffer, no intermediate allocations
- **Compile-time polymorphism** — `coff_file<pe32_traits>` / `coff_file<pe32plus_traits>` with zero virtual dispatch
- **No exceptions** — `result<T, E>` with monadic `map()` / `and_then()` for composable error handling
- **Lazy evaluation** — sections, symbols, imports are iterated on demand, never materialized into vectors
- **Composable pipe syntax** — `file.sections() | filter(...) | transform(...)` (C++20 Ranges style, in C++17)
- **Overflow-safe** — all arithmetic through `checked_add` / `checked_mul`, guards against malicious PE files

## Requirements

- C++17 compiler (GCC 7+, Clang 5+, MSVC 2017+)
- CMake 3.20+
- Ninja (recommended) or Make
- Google Test (auto-fetched via `FetchContent`)

## Building

```bash
cmake -B build -S coffi-modern -G Ninja
ninja -C build
ctest --test-dir build
```

If your system doesn't have Google Test installed:

```bash
cmake -B build -S coffi-modern -G Ninja -DCOFFI_FETCH_GTEST=ON
```

Build options:

| Option | Default | Description |
|--------|---------|-------------|
| `COFFI_BUILD_TESTS` | `ON` | Build test suite |
| `COFFI_BUILD_EXAMPLES` | `ON` | Build example programs |
| `COFFI_FETCH_GTEST` | `OFF` | Auto-download GTest via FetchContent if not found |

## Quick Start

### Basic: Read PE sections

```cpp
#include <coffi/coffi.hpp>
#include <iostream>

int main() {
    // Load file into memory
    auto buf = coffi::file_buffer::from_file("notepad.exe");
    if (!buf) return 1;

    // Parse as PE32 (use pe32plus_traits for 64-bit)
    auto file = coffi::coff_file<coffi::pe32_traits>::from_view(buf->view());
    if (!file) {
        std::cerr << coffi::to_string(file.error()) << "\n";
        return 1;
    }

    // Lazy iteration — no memory allocated for section objects
    for (auto sec : file->sections()) {
        std::cout << sec.name()
                  << "  VA=0x" << std::hex << sec.virtual_address()
                  << "  size=" << std::dec << sec.data_size()
                  << "\n";
    }
}
```

### Auto-detect architecture

```cpp
auto buf = coffi::file_buffer::from_file("app.exe");
auto file = coffi::auto_load(buf->view());  // returns std::variant<pe32, pe32+>
if (!file) { /* handle error */ }

std::visit([](auto& f) {
    for (auto sec : f.sections())
        std::cout << sec.name() << "\n";
}, *file);
```

### Pipe syntax: filter and transform

```cpp
// Find all executable sections and extract their names
auto names = file->sections()
    | coffi::filter([](auto s) { return s.is_executable(); })
    | coffi::transform([](auto s) { return s.name(); });

for (auto name : names)
    std::cout << name << "\n";
```

### Error handling with result<T, E>

```cpp
// Monadic chaining — no if-checking needed
auto entry_point = file->optional_header()
    .map([](auto h) { return h.entry_point_address; });

if (entry_point)
    std::cout << "Entry: 0x" << std::hex << *entry_point << "\n";
else
    std::cerr << coffi::to_string(entry_point.error()) << "\n";
```

### Memory-mapped file (zero-copy from mmap)

```cpp
// coffi-modern doesn't call mmap itself (that's OS-specific),
// but it's designed to work directly with mmap'd memory:
void* mapped = mmap(nullptr, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
coffi::byte_view data(mapped, file_size);
auto file = coffi::coff_file<coffi::pe32plus_traits>::from_view(data);
// Everything parsed directly from the mapped pages — true zero-copy
```

## Architecture

```
coffi.hpp                          ← single-include entry point
├── core/
│   ├── error.hpp                  ← error_code enum + to_string()
│   ├── result.hpp                 ← result<T,E> with map/and_then
│   ├── safe_math.hpp              ← checked_add/mul, align_to
│   ├── endian.hpp                 ← byte_swap, to_native/from_native
│   ├── byte_view.hpp              ← non-owning byte span, memcpy-based reads
│   └── lazy.hpp                   ← filter | transform | take_while
├── platform/
│   ├── schema.hpp                 ← packed PE/COFF structs (static_assert'd)
│   └── traits.hpp                 ← pe32_traits / pe32plus_traits
└── views/
    ├── string_table.hpp           ← zero-copy COFF name resolution
    ├── rva_resolver.hpp           ← safe RVA → file offset mapping
    ├── section_view.hpp           ← section_ref + section_range
    ├── symbol_view.hpp            ← symbol_ref + symbol_range
    └── import_view.hpp            ← import_module_ref + import_symbol_ref
```

### Design Decisions

| Concern | Traditional (COFFI) | Modern (coffi-modern) |
|---------|--------------------|-----------------------|
| Polymorphism | `virtual` functions | `template <typename Traits>` |
| Memory | `unique_ptr<char[]>` eager load | `byte_view` zero-copy lazy |
| Errors | `bool` returns / exceptions | `result<T, error_code>` monadic |
| Alignment | `reinterpret_cast` (UB risk) | `std::memcpy` (optimized by compiler) |
| Overflow | unchecked arithmetic | `checked_add` / `checked_mul` |
| Iteration | `std::vector<section>` | lazy `section_range` + pipe `\|` |
| String access | `std::string` copies | `std::string_view` into file buffer |

## Examples

Three example programs are included in `examples/`:

| Program | Description |
|---------|-------------|
| `pe_info` | Print PE headers, section table with flags |
| `dump_symbols` | List all COFF symbols with pipe-filter demo |
| `dump_imports` | Walk the import directory table |

```bash
# After building:
./build/examples/pe_info /path/to/notepad.exe
./build/examples/dump_imports /path/to/notepad.exe
./build/examples/dump_symbols /path/to/some.obj
```

## Tests

67 test cases across 5 suites:

| Suite | Tests | Covers |
|-------|-------|--------|
| `core_test` | 31 | result, byte_view, safe_math, endian |
| `lazy_test` | 10 | filter, transform, take_while, pipe chains |
| `schema_test` | 3 | struct sizes, field offsets, magic constants |
| `view_test` | 9 | section range, symbol range, string table, RVA resolver |
| `coff_file_test` | 14 | PE32 parsing, auto-detection, error handling, pipe integration |

## License

Same license as the original COFFI project.
