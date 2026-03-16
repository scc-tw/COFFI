cmake_minimum_required(VERSION 3.14)

include(FetchContent)

FetchContent_Declare(
    googlebenchmark
    GIT_REPOSITORY https://github.com/google/benchmark.git
    GIT_TAG        v1.9.1
)

set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(BENCHMARK_ENABLE_INSTALL OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googlebenchmark)

add_executable(coffi_bench coffi_bench.cpp)
target_link_libraries(coffi_bench PRIVATE coffi::coffi benchmark::benchmark benchmark::benchmark_main)
target_compile_features(coffi_bench PRIVATE cxx_std_17)

# Copy test data
add_custom_command(TARGET coffi_bench POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
    ${CMAKE_CURRENT_SOURCE_DIR}/../tests/data
    $<TARGET_FILE_DIR:coffi_bench>/data)
