cmake_minimum_required(VERSION 3.13)
set(CMAKE_C_STANDARD 99)

project(honey_mirror C)
add_executable(honey_mirror
        honey_mirror/main.c
        honey_mirror/disassembly/elf.h
        honey_mirror/disassembly/hm_disassembly.c
        honey_mirror/disassembly/hm_disassembly.h
        honey_mirror/code_generation/hm_code_generator.c
        honey_mirror/code_generation/hm_code_generator.h)
target_include_directories(honey_mirror PRIVATE ${CMAKE_SOURCE_DIR}/dependencies/xed/obj/wkit/include/xed)
target_link_libraries(honey_mirror ${CMAKE_SOURCE_DIR}/dependencies/xed/obj/libxed.a)

project(honey_analyzer C ASM)
add_executable(honey_analyzer
        honey_analyzer/main.c
        honey_analyzer/trace_analysis/ha_mirror_block_decode_thunks.asm
        /tmp/mirror.S
        honey_analyzer/trace_analysis/ha_session.c
        honey_analyzer/trace_analysis/ha_session.h
        honey_analyzer/trace_analysis/ha_mirror_utils.h
        honey_analyzer/trace_analysis/ha_mirror_utils.c
        honey_analyzer/processor_trace/ha_pt_decoder.c
        honey_analyzer/processor_trace/ha_pt_decoder.h
        honey_analyzer/ha_debug_switch.h
        honey_analyzer/unit_testing/ha_session_audit.c
        honey_analyzer/unit_testing/ha_session_audit.h
        honey_analyzer/trace_analysis/ha_session_internal.h)
target_compile_options(honey_analyzer PRIVATE -masm=intel)
#target_compile_options(honey_analyzer PRIVATE -ftime-report)
target_compile_options(honey_analyzer PRIVATE -Ofast)
target_compile_options(honey_analyzer PRIVATE -g0)
#target_compile_options(honey_analyzer PRIVATE -fno-omit-frame-pointer -fsanitize=address)
#target_link_options(honey_analyzer PRIVATE -fno-omit-frame-pointer -fsanitize=address)
target_include_directories(honey_analyzer PRIVATE ${CMAKE_SOURCE_DIR}/dependencies/libipt/libipt/include)
target_link_libraries(honey_analyzer ${CMAKE_SOURCE_DIR}/dependencies/libipt/lib/libipt.a)
