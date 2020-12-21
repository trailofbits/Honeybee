cmake_minimum_required(VERSION 3.17)
project(Honeybee C)

set(CMAKE_C_STANDARD 99)

add_executable(Honeybee honey_mirror/main.c)

target_include_directories(Honeybee PRIVATE ${CMAKE_SOURCE_DIR}/dependencies/xed/obj/wkit/include/xed)
target_link_libraries(Honeybee ${CMAKE_SOURCE_DIR}/dependencies/xed/obj/libxed.a)

