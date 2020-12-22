cmake_minimum_required(VERSION 3.17)
set(CMAKE_C_STANDARD 99)

project(honey_mirror C)
add_executable(honey_mirror honey_mirror/main.c honey_mirror/disassembly/elf.h honey_mirror/disassembly/hm_disassembly.c
        honey_mirror/disassembly/hm_disassembly.h honey_mirror/code_generation/hm_code_generator.c
        honey_mirror/code_generation/hm_code_generator.h)
target_include_directories(honey_mirror PRIVATE ${CMAKE_SOURCE_DIR}/dependencies/xed/obj/wkit/include/xed)
target_link_libraries(honey_mirror ${CMAKE_SOURCE_DIR}/dependencies/xed/obj/libxed.a)

project(honey_analyzer C ASM)
#set_property(SOURCE ../test.s PROPERTY LANGUAGE C)
add_executable(honey_analyzer
        honey_analyzer/main.c
        ../test.s
        )
target_compile_options(honey_analyzer PRIVATE -masm=intel)
target_include_directories(honey_analyzer PRIVATE ${CMAKE_SOURCE_DIR}/dependencies/libipt/libipt/include)
target_link_libraries(honey_analyzer ${CMAKE_SOURCE_DIR}/dependencies/libipt/lib/libipt.a)


#if(CMAKE_BUILD_TYPE STREQUAL "Debug")
#    target_compile_options(honey_mirror PRIVATE -fno-omit-frame-pointer -fsanitize=address)
#    target_link_options(honey_mirror PRIVATE -fno-omit-frame-pointer -fsanitize=address)
#endif()
