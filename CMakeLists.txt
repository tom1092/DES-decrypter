cmake_minimum_required(VERSION 3.8)
project(ompDES_cracker)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_COMPILER "/usr/bin/clang++")
set(CMAKE_CXX_FLAGS "-fopenmp -std=c++11")
set(SOURCE_FILES main.cpp crypt3.h ArgsParser.h)
add_executable(ompDES_cracker ${SOURCE_FILES})

find_library(libcrypt3 NAMES crypt3)
message("Lib is at: ${libcrypt3}")
link_directories(${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(ompDES_cracker crypt3)

