cmake_minimum_required(VERSION 3.15)

project(Embedded-SecLink 
    VERSION 0.9.9
    LANGUAGES CXX C
)


option(ESL_BUILD_SHARED "Build ESL as a shared library(.dll)" OFF)
option(ESL_BUILD_TESTS "Build test suite" OFF)
option(ESL_BUILD_EXAMPLES "Build examples" ON)
option(ESL_STRICT_MODE "Enable strict compilation warnings" OFF)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(FetchContent)
if(ESL_BUILD_TESTS)
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

message(STATUS "Fetching blst ...")
FetchContent_Declare(
    blst
    GIT_REPOSITORY https://github.com/supranational/blst.git
    GIT_TAG        v0.3.15  # 建議綁一個 release tag，避免 API 演進造成破壞 [web:20]
)
FetchContent_MakeAvailable(blst)
FetchContent_GetProperties(blst SOURCE_DIR blst_SOURCE_DIR)

message(STATUS "Fetching micro-ecc....")
FetchContent_Declare(
    micro_ecc 
    GIT_REPOSITORY https://github.com/kmackay/micro-ecc.git
    GIT_TAG        master   
)

FetchContent_MakeAvailable(micro_ecc)
FetchContent_GetProperties(micro_ecc SOURCE_DIR uECC_SOURCE_DIR)

message(STATUS "Fetching PicoSHA2")
FetchContent_Declare(
    picosha2
    GIT_REPOSITORY https://github.com/okdshin/PicoSHA2.git
    GIT_TAG        master
)
FetchContent_MakeAvailable(picosha2)
FetchContent_GetProperties(picosha2 SOURCE_DIR picosha2_SOURCE_DIR)

message(STATUS "Fetching tiny-AES-c...")
FetchContent_Declare(
    tiny_aes
    GIT_REPOSITORY https://github.com/kokke/tiny-AES-c.git
    GIT_TAG        master
)
FetchContent_MakeAvailable(tiny_aes)
FetchContent_GetProperties(tiny_aes SOURCE_DIR aes_SOURCE_DIR)



add_subdirectory(src)

if(ESL_BUILD_EXAMPLES) #test first
    add_subdirectory(examples)
endif()

if(ESL_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()