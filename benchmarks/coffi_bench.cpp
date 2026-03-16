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
