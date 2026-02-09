cmake_minimum_required(VERSION 3.22.1)
project("nativectf" C)

# Common flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra")

# Flag HMAC verification (shared utility)
add_library(flag_core STATIC flag_core.c)
target_include_directories(flag_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# -- Challenge 01: String Maze --
add_library(ch01_stringmaze SHARED ch01_stringmaze.c)
target_link_libraries(ch01_stringmaze flag_core log)

# -- Challenge 02: Stack Smasher --
add_library(ch02_stacksmasher SHARED ch02_stacksmasher.c)
target_compile_options(ch02_stacksmasher PRIVATE -fno-stack-protector -z execstack)
target_link_libraries(ch02_stacksmasher flag_core log)

# -- Challenge 03: JNI Type Confusion --
add_library(ch03_typeconfusion SHARED ch03_typeconfusion.c)
target_link_libraries(ch03_typeconfusion flag_core log)

# -- Challenge 04: Anti-Debug Gauntlet --
add_library(ch04_gauntlet SHARED ch04_gauntlet.c)
target_link_libraries(ch04_gauntlet flag_core log)

# -- Challenge 05: Heap Feng Shui --
add_library(ch05_heapcraft SHARED ch05_heapcraft.c)
target_link_libraries(ch05_heapcraft flag_core log)

# -- Challenge 06: Custom VM --
add_library(ch06_vm SHARED ch06_vm.c)
target_link_libraries(ch06_vm flag_core log)
