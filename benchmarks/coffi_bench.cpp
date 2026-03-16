#include <benchmark/benchmark.h>
#include <coffi/coffi.hpp>
#include <fstream>
#include <sstream>

using namespace COFFI;

// Helper: load file into memory buffer for consistent I/O
static std::string read_file_to_string(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

// ---------------------------------------------------------------------------
// LOAD benchmarks
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Stats — run once to understand file structure
// ---------------------------------------------------------------------------
static void BM_Stats_OBJ(benchmark::State& state) {
    auto buf = read_file_to_string("data/coffi_test.obj");
    coffi c;
    std::istringstream ss(buf, std::ios::binary);
    c.load(ss);
    auto* syms = c.get_symbols();
    uint32_t total_relocs = 0;
    for (const auto& sec : c.get_sections())
        total_relocs += sec.get_reloc_count();
    state.counters["symbols"] = syms ? syms->size() : 0;
    state.counters["sections"] = c.get_sections().get_count();
    state.counters["relocations"] = total_relocs;
    for (auto _ : state) {
        std::istringstream ss2(buf, std::ios::binary);
        coffi c2;
        benchmark::DoNotOptimize(c2.load(ss2));
    }
}
BENCHMARK(BM_Stats_OBJ);

static void BM_Load_PE_Small(benchmark::State& state) {
    auto buf = read_file_to_string("data/label.exe"); // 2 KB
    for (auto _ : state) {
        std::istringstream ss(buf, std::ios::binary);
        coffi c;
        benchmark::DoNotOptimize(c.load(ss));
    }
    state.SetBytesProcessed(state.iterations() * buf.size());
}
BENCHMARK(BM_Load_PE_Small);

static void BM_Load_PE_Medium(benchmark::State& state) {
    auto buf = read_file_to_string("data/notepad.exe"); // 193 KB
    for (auto _ : state) {
        std::istringstream ss(buf, std::ios::binary);
        coffi c;
        benchmark::DoNotOptimize(c.load(ss));
    }
    state.SetBytesProcessed(state.iterations() * buf.size());
}
BENCHMARK(BM_Load_PE_Medium);

static void BM_Load_PE_Large(benchmark::State& state) {
    auto buf = read_file_to_string("data/NikPEViewer.exe"); // 196 KB
    for (auto _ : state) {
        std::istringstream ss(buf, std::ios::binary);
        coffi c;
        benchmark::DoNotOptimize(c.load(ss));
    }
    state.SetBytesProcessed(state.iterations() * buf.size());
}
BENCHMARK(BM_Load_PE_Large);

static void BM_Load_OBJ(benchmark::State& state) {
    auto buf = read_file_to_string("data/coffi_test.obj"); // 462 KB
    for (auto _ : state) {
        std::istringstream ss(buf, std::ios::binary);
        coffi c;
        benchmark::DoNotOptimize(c.load(ss));
    }
    state.SetBytesProcessed(state.iterations() * buf.size());
}
BENCHMARK(BM_Load_OBJ);

static void BM_Load_DLL(benchmark::State& state) {
    auto buf = read_file_to_string("data/espui.dll"); // 28 KB
    for (auto _ : state) {
        std::istringstream ss(buf, std::ios::binary);
        coffi c;
        benchmark::DoNotOptimize(c.load(ss));
    }
    state.SetBytesProcessed(state.iterations() * buf.size());
}
BENCHMARK(BM_Load_DLL);

// ---------------------------------------------------------------------------
// SAVE benchmarks (load once, benchmark save)
// ---------------------------------------------------------------------------

static void BM_Save_PE_Medium(benchmark::State& state) {
    auto buf = read_file_to_string("data/notepad.exe");
    coffi c;
    {
        std::istringstream ss(buf, std::ios::binary);
        c.load(ss);
    }
    for (auto _ : state) {
        std::ostringstream ss(std::ios::binary);
        benchmark::DoNotOptimize(c.save(ss));
    }
    state.SetBytesProcessed(state.iterations() * buf.size());
}
BENCHMARK(BM_Save_PE_Medium);

static void BM_Save_PE_Large(benchmark::State& state) {
    auto buf = read_file_to_string("data/NikPEViewer.exe");
    coffi c;
    {
        std::istringstream ss(buf, std::ios::binary);
        c.load(ss);
    }
    for (auto _ : state) {
        std::ostringstream ss(std::ios::binary);
        benchmark::DoNotOptimize(c.save(ss));
    }
    state.SetBytesProcessed(state.iterations() * buf.size());
}
BENCHMARK(BM_Save_PE_Large);

// ---------------------------------------------------------------------------
// Checksum benchmark (isolated — this is the hot loop in save)
// ---------------------------------------------------------------------------

static void BM_Save_Checksum_Only(benchmark::State& state) {
    // Create a PE file in memory to benchmark checksum computation
    auto buf = read_file_to_string("data/NikPEViewer.exe");
    coffi c;
    {
        std::istringstream ss(buf, std::ios::binary);
        c.load(ss);
    }
    // Pre-save to get a valid stream
    std::string saved;
    {
        std::ostringstream ss(std::ios::binary);
        c.save(ss);
        saved = ss.str();
    }
    for (auto _ : state) {
        std::istringstream src(saved, std::ios::binary);
        std::ostringstream dst(std::ios::binary);
        benchmark::DoNotOptimize(c.save(dst));
    }
    state.SetBytesProcessed(state.iterations() * saved.size());
}
BENCHMARK(BM_Save_Checksum_Only);

// ---------------------------------------------------------------------------
// Section lookup benchmarks
// ---------------------------------------------------------------------------

static void BM_SectionLookup_ByName(benchmark::State& state) {
    auto buf = read_file_to_string("data/notepad.exe");
    coffi c;
    {
        std::istringstream ss(buf, std::ios::binary);
        c.load(ss);
    }
    for (auto _ : state) {
        benchmark::DoNotOptimize(c.get_sections()[".text"]);
        benchmark::DoNotOptimize(c.get_sections()[".rdata"]);
        benchmark::DoNotOptimize(c.get_sections()[".rsrc"]);
    }
}
BENCHMARK(BM_SectionLookup_ByName);

// ---------------------------------------------------------------------------
// Symbol lookup benchmarks
// ---------------------------------------------------------------------------

static void BM_SymbolLookup_ByIndex(benchmark::State& state) {
    auto buf = read_file_to_string("data/coffi_test.obj");
    coffi c;
    {
        std::istringstream ss(buf, std::ios::binary);
        c.load(ss);
    }
    auto* syms = c.get_symbols();
    if (!syms || syms->empty()) {
        state.SkipWithMessage("No symbols");
        return;
    }
    uint32_t max_idx = syms->back().get_index();
    for (auto _ : state) {
        for (uint32_t i = 0; i <= max_idx; i += 10) {
            benchmark::DoNotOptimize(c.get_symbol(i));
        }
    }
}
BENCHMARK(BM_SymbolLookup_ByIndex);

// ---------------------------------------------------------------------------
// Stress tests: synthetic large PE and heavy symbol tables
// ---------------------------------------------------------------------------

// Generate a large PE with many sections and large data
static std::string generate_large_pe(int num_sections, int data_per_section) {
    coffi c;
    c.create(COFFI_ARCHITECTURE_PE);
    c.create_optional_header();

    std::vector<char> filler(data_per_section, '\xCC');
    for (int i = 0; i < num_sections; ++i) {
        std::string name = ".s" + std::to_string(i);
        auto* sec = c.add_section(name);
        sec->set_data(filler.data(), static_cast<uint32_t>(filler.size()));
        sec->set_virtual_address(0x1000 * (i + 1));
        sec->set_virtual_size(data_per_section);
        sec->set_flags(IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ);
    }

    std::ostringstream out(std::ios::binary);
    c.save(out);
    return out.str();
}

// Generate an OBJ with many symbols and relocations
static std::string generate_heavy_obj(int num_symbols, int num_sections,
                                       int relocs_per_section) {
    coffi c;
    c.create(COFFI_ARCHITECTURE_PE);

    // Add symbols
    for (int i = 0; i < num_symbols; ++i) {
        std::string name = "_sym_" + std::to_string(i);
        auto* sym = c.add_symbol(name);
        sym->set_section_number(1);
        sym->set_value(i * 4);
        sym->set_type(0x20);
        sym->set_storage_class(2);
    }

    // Add sections with relocations
    for (int i = 0; i < num_sections; ++i) {
        std::string name = ".t" + std::to_string(i);
        auto* sec = c.add_section(name);
        // Need enough data to hold the relocations
        uint32_t data_size = relocs_per_section * 4 + 256;
        std::vector<char> data(data_size, '\x90');
        sec->set_data(data.data(), data_size);
        sec->set_flags(IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ |
                        IMAGE_SCN_MEM_EXECUTE);

        for (int r = 0; r < relocs_per_section; ++r) {
            rel_entry_generic entry{};
            entry.virtual_address = r * 4;
            entry.symbol_table_index = r % num_symbols;
            entry.type = 0x14; // IMAGE_REL_I386_DIR32
            sec->add_relocation_entry(&entry);
        }
    }

    std::ostringstream out(std::ios::binary);
    c.save(out);
    return out.str();
}

// --- Large PE benchmarks ---

static void BM_Load_LargePE_50sec_64KB(benchmark::State& state) {
    auto buf = generate_large_pe(50, 65536); // 50 sections × 64KB = ~3.2MB
    state.counters["file_size"] = buf.size();
    for (auto _ : state) {
        std::istringstream ss(buf, std::ios::binary);
        coffi c;
        benchmark::DoNotOptimize(c.load(ss));
    }
    state.SetBytesProcessed(state.iterations() * buf.size());
}
BENCHMARK(BM_Load_LargePE_50sec_64KB);

static void BM_Save_LargePE_50sec_64KB(benchmark::State& state) {
    auto buf = generate_large_pe(50, 65536);
    coffi c;
    { std::istringstream ss(buf, std::ios::binary); c.load(ss); }
    for (auto _ : state) {
        std::ostringstream ss(std::ios::binary);
        benchmark::DoNotOptimize(c.save(ss));
    }
    state.SetBytesProcessed(state.iterations() * buf.size());
}
BENCHMARK(BM_Save_LargePE_50sec_64KB);

static void BM_Load_LargePE_200sec_256KB(benchmark::State& state) {
    auto buf = generate_large_pe(200, 262144); // 200 sections × 256KB = ~50MB
    state.counters["file_size"] = buf.size();
    for (auto _ : state) {
        std::istringstream ss(buf, std::ios::binary);
        coffi c;
        benchmark::DoNotOptimize(c.load(ss));
    }
    state.SetBytesProcessed(state.iterations() * buf.size());
}
BENCHMARK(BM_Load_LargePE_200sec_256KB);

static void BM_Save_LargePE_200sec_256KB(benchmark::State& state) {
    auto buf = generate_large_pe(200, 262144);
    coffi c;
    { std::istringstream ss(buf, std::ios::binary); c.load(ss); }
    for (auto _ : state) {
        std::ostringstream ss(std::ios::binary);
        benchmark::DoNotOptimize(c.save(ss));
    }
    state.SetBytesProcessed(state.iterations() * buf.size());
}
BENCHMARK(BM_Save_LargePE_200sec_256KB);

// --- Heavy symbol table benchmarks ---

static void BM_Load_HeavyOBJ_10Ksym_50sec_100reloc(benchmark::State& state) {
    auto buf = generate_heavy_obj(10000, 50, 100); // 10K symbols, 5K relocs
    state.counters["file_size"] = buf.size();
    for (auto _ : state) {
        std::istringstream ss(buf, std::ios::binary);
        coffi c;
        benchmark::DoNotOptimize(c.load(ss));
    }
    state.SetBytesProcessed(state.iterations() * buf.size());
}
BENCHMARK(BM_Load_HeavyOBJ_10Ksym_50sec_100reloc);

static void BM_Load_HeavyOBJ_50Ksym_100sec_500reloc(benchmark::State& state) {
    auto buf = generate_heavy_obj(50000, 100, 500); // 50K symbols, 50K relocs
    state.counters["file_size"] = buf.size();
    for (auto _ : state) {
        std::istringstream ss(buf, std::ios::binary);
        coffi c;
        benchmark::DoNotOptimize(c.load(ss));
    }
    state.SetBytesProcessed(state.iterations() * buf.size());
}
BENCHMARK(BM_Load_HeavyOBJ_50Ksym_100sec_500reloc);

// Extreme: simulate a large debug build OBJ
static void BM_Load_HeavyOBJ_100Ksym_200sec_1000reloc(benchmark::State& state) {
    auto buf = generate_heavy_obj(100000, 200, 1000); // 100K sym, 200K relocs
    state.counters["file_size"] = buf.size();
    for (auto _ : state) {
        std::istringstream ss(buf, std::ios::binary);
        coffi c;
        benchmark::DoNotOptimize(c.load(ss));
    }
    state.SetBytesProcessed(state.iterations() * buf.size());
}
BENCHMARK(BM_Load_HeavyOBJ_100Ksym_200sec_1000reloc);

// ---------------------------------------------------------------------------
// Use-case benchmark: extract all function boundaries from symbol table
// Simulates: iterate symbols, filter by type, get name + address + size
// ---------------------------------------------------------------------------

static void BM_UseCase_FunctionBoundaries_CurrentAPI(benchmark::State& state) {
    auto buf = generate_heavy_obj(100000, 200, 1000);
    for (auto _ : state) {
        std::istringstream ss(buf, std::ios::binary);
        coffi c;
        c.load(ss);

        auto* syms = c.get_symbols();
        uint32_t func_count = 0;
        if (syms) {
            for (const auto& sym : *syms) {
                // Filter: ISFCN(type) = type & 0x20
                if (sym.get_type() & 0x20) {
                    auto name = sym.get_name(); // std::string alloc!
                    auto addr = sym.get_value();
                    auto sec  = sym.get_section_number();
                    benchmark::DoNotOptimize(name);
                    benchmark::DoNotOptimize(addr);
                    benchmark::DoNotOptimize(sec);
                    func_count++;
                }
            }
        }
        state.counters["functions"] = func_count;
    }
}
BENCHMARK(BM_UseCase_FunctionBoundaries_CurrentAPI);

// Same use case but with load_symbols_only + zero-copy raw iteration
static void BM_UseCase_FunctionBoundaries_FastPath(benchmark::State& state) {
    auto buf = generate_heavy_obj(100000, 200, 1000);
    for (auto _ : state) {
        std::istringstream ss(buf, std::ios::binary);
        coffi c;
        c.load_symbols_only(ss);

        const symbol_record* records = c.get_symbol_records();
        uint32_t count = c.get_symbol_records_count();
        uint32_t func_count = 0;

        for (uint32_t i = 0; i < count; ++i) {
            const auto& rec = records[i];
            if (rec.type & 0x20) { // ISFCN
                auto name = c.string_to_name_view(rec.name);
                auto addr = rec.value;
                auto sec  = rec.section_number;
                benchmark::DoNotOptimize(name);
                benchmark::DoNotOptimize(addr);
                benchmark::DoNotOptimize(sec);
                func_count++;
            }
            i += rec.aux_symbols_number; // skip aux records
        }
        state.counters["functions"] = func_count;
    }
}
BENCHMARK(BM_UseCase_FunctionBoundaries_FastPath);
