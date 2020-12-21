cmake_minimum_required(VERSION 3.17)
set(CMAKE_C_STANDARD 99)

project(honey_mirror C)
add_executable(honey_mirror honey_mirror/main.c honey_mirror/disassembly/elf.h honey_mirror/disassembly/hm_disassembly.c honey_mirror/disassembly/hm_disassembly.h)
target_include_directories(honey_mirror PRIVATE ${CMAKE_SOURCE_DIR}/dependencies/xed/obj/wkit/include/xed)
target_link_libraries(honey_mirror ${CMAKE_SOURCE_DIR}/dependencies/xed/obj/libxed.a)
target_compile_options(honey_mirror PRIVATE -fblocks)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(honey_mirror PRIVATE -fno-omit-frame-pointer -fsanitize=address)
    target_link_options(honey_mirror PRIVATE -fno-omit-frame-pointer -fsanitize=address)
endif()
