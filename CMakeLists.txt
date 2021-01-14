cmake_minimum_required(VERSION 3.13)
set(CMAKE_C_STANDARD 99)

project(honey_hive_generator C)
add_executable(honey_hive_generator
        honey_hive_generator/main.c
        honey_hive_generator/disassembly/elf.h
        honey_hive_generator/disassembly/hh_disassembly.c
        honey_hive_generator/disassembly/hh_disassembly.h
        honey_hive_generator/hive_generation/hh_hive_generator.c
        honey_hive_generator/hive_generation/hh_hive_generator.h
        honeybee_shared/hb_hive.h)
target_include_directories(honey_hive_generator PRIVATE ${CMAKE_SOURCE_DIR}/dependencies/xed/obj/wkit/include/xed)
target_link_libraries(honey_hive_generator ${CMAKE_SOURCE_DIR}/dependencies/xed/obj/libxed.a)

project(honey_analyzer C)
add_library(honey_analyzer STATIC
        honey_analyzer/trace_analysis/ha_session.c
        honey_analyzer/trace_analysis/ha_session.h
        honey_analyzer/processor_trace/ha_pt_decoder.c
        honey_analyzer/processor_trace/ha_pt_decoder.h
        honey_analyzer/ha_debug_switch.h
        honey_analyzer/trace_analysis/ha_session_internal.h
        honey_analyzer/capture/ha_capture_session.c
        honey_analyzer/capture/ha_capture_session.h
        honeybee_shared/hb_hive.c
        honeybee_shared/hb_hive.h honey_analyzer/processor_trace/ha_pt_decoder_constants.h honey_analyzer/honey_analyzer.h)
target_compile_options(honey_analyzer PRIVATE -Ofast)

#For ease of debugging, we don't actually link against honey_analyzer in honey_tester since CMake does not recursively
#detect changes.
project(honey_tester C)
add_executable(honey_tester
        honey_tester/main.c
        honey_tester/unit_testing/ha_session_audit.c
        honey_tester/unit_testing/ha_session_audit.h
        honey_analyzer/trace_analysis/ha_session.c
        honey_analyzer/trace_analysis/ha_session.h
        honey_analyzer/processor_trace/ha_pt_decoder.c
        honey_analyzer/processor_trace/ha_pt_decoder.h
        honey_analyzer/ha_debug_switch.h
        honey_analyzer/capture/ha_capture_session.c
        honey_analyzer/capture/ha_capture_session.h
        honey_analyzer/trace_analysis/ha_session_internal.h
        honeybee_shared/hb_hive.c
        honeybee_shared/hb_hive.h honey_analyzer/processor_trace/ha_pt_decoder_constants.h honey_analyzer/honey_analyzer.h)
target_include_directories(honey_tester PRIVATE ${CMAKE_SOURCE_DIR}/dependencies/libipt/libipt/include)
target_link_libraries(honey_tester ${CMAKE_SOURCE_DIR}/dependencies/libipt/lib/libipt.a)
#target_compile_options(honey_tester PRIVATE -Ofast)
#target_compile_options(honey_analyzer PRIVATE -fno-omit-frame-pointer -fsanitize=address)
#target_link_options(honey_analyzer PRIVATE -fno-omit-frame-pointer -fsanitize=address)
