cmake_minimum_required(VERSION 3.20)

project(coffi-modern VERSION 2.0.0 LANGUAGES C CXX)

# --- Options ---
option(COFFI_BUILD_TESTS "Build COFFI-Modern tests" ON)
option(COFFI_BUILD_EXAMPLES "Build COFFI-Modern examples" ON)

# --- C++ Standard ---
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# --- Build Tools ---
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    message(STATUS "Setting build type to 'Release' as none was specified.")
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Choose the type of build." FORCE)
endif()

# --- Library Target ---
add_library(coffi-modern INTERFACE)
add_library(coffi::coffi-modern ALIAS coffi-modern)

target_include_directories(
    coffi-modern
    INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

# --- Dependencies (Google Test) ---
if(COFFI_BUILD_TESTS)
    include(FetchContent)
    FetchContent_Declare(
      googletest
      URL https://github.com/google/googletest/archive/refs/tags/v1.13.0.zip
    )
    # For Windows: prevent gtest from overriding our compiler's runtime settings
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)

    enable_testing()
    add_subdirectory(tests)
endif()

if(COFFI_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()
