cmake_minimum_required(VERSION 3.15)

project(Embedded-SecLink 
    VERSION 0.1.0 
    LANGUAGES CXX C
)

option(ESL_BUILD_SHARED "Build ESL as a shared library" OFF)
option(ESL_BUILD_TESTS "Build test suite" ON)
option(ESL_BUILD_EXAMPLES "Build examples" ON)
option(ESL_STRICT_MODE "Enable strict compilation warnings" ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)


if(ESL_BUILD_TESTS)
    include(FetchContent)
    message(STATUS "Fetching GoogleTest...")
    FetchContent_Declare(
        googletest
        URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    )
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)
endif()


set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

include(FetchContent)
message(STATUS "Fetching mcl (High-performance BLS)...")
FetchContent_Declare(
    mcl
    GIT_REPOSITORY https://github.com/herumi/mcl.git
    GIT_TAG        v1.93 
)

set(MCL_STATIC_LIB ON CACHE BOOL "" FORCE)
set(MCL_USE_LLVM OFF CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(mcl)

if(NOT TARGET mcl::mcl)
    add_library(mcl::mcl ALIAS mcl)
endif()

add_subdirectory(src)

if(ESL_BUILD_EXAMPLES) #test first
    add_subdirectory(examples)
endif()

if(ESL_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()