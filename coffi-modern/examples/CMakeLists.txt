function(coffi_add_example name)
    add_executable(${name} ${name}.cpp)
    target_link_libraries(${name} PRIVATE coffi::coffi-modern)
endfunction()

coffi_add_example(pe_info)
coffi_add_example(dump_symbols)
coffi_add_example(dump_imports)
