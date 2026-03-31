find_package(Boost REQUIRED COMPONENTS unit_test_framework)

# Import section accessor tests
add_executable(coffi_import_test coffi_import_test.cpp)
target_link_libraries(coffi_import_test PRIVATE coffi::coffi Boost::unit_test_framework)
add_test(NAME coffi_import_test COMMAND coffi_import_test WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
add_dependencies(check coffi_import_test)
