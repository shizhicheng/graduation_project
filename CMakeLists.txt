cmake_minimum_required(VERSION 3.8)
project(graduation_project)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_FLAGS "-glldb -Wall -O0")

set(SOURCE_FILES main.cpp sha512.h sha512.cpp shacal.h shacal.cpp test.h test.cpp index.h index.cpp)
add_executable(graduation_project ${SOURCE_FILES})