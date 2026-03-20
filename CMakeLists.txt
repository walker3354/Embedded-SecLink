cmake_minimum_required(VERSION 3.12)

project(Embedded-SecLink 
    VERSION 1.1.0
    LANGUAGES CXX C
)


# ===== Options =====
option(ESL_BUILD_SHARED "Build ESL as a shared library(.dll)" OFF)
option(ESL_BUILD_TESTS "Build test suite" OFF)
option(ESL_BUILD_EXAMPLES "Build examples" ON)
option(ESL_STRICT_MODE "Enable strict compilation warnings" OFF)

# ===== C++ Standard =====
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ===== Install Dirs =====
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

# ===== Output Dirs =====
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# ===== FetchContent =====
include(FetchContent)
if(ESL_BUILD_TESTS)
    message(STATUS "Fetching GoogleTest...")
    FetchContent_Declare(
        googletest
        URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    )
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    
    FetchContent_GetProperties(googletest)
    if(NOT googletest_POPULATED)
        FetchContent_Populate(googletest)
        add_subdirectory(${googletest_SOURCE_DIR} ${googletest_BINARY_DIR})
    endif()
endif()

message(STATUS "Fetching blst ...")
FetchContent_Declare(
    blst
    GIT_REPOSITORY https://github.com/supranational/blst.git
    GIT_TAG        v0.3.13
)

FetchContent_GetProperties(blst)
if(NOT blst_POPULATED)
    FetchContent_Populate(blst)
    
    set(BLST_SOURCES "${blst_SOURCE_DIR}/src/server.c")
    
    if(MSVC AND CMAKE_SIZEOF_VOID_P EQUAL 8)
        file(GLOB BLST_ASM_SOURCES 
            "${blst_SOURCE_DIR}/build/win64/*-x86_64.asm"
        )
        
        if(BLST_ASM_SOURCES)
            list(APPEND BLST_SOURCES ${BLST_ASM_SOURCES})
            enable_language(ASM_MASM)
        endif()
    endif()
    
    add_library(blst STATIC ${BLST_SOURCES})
    
    target_include_directories(blst 
        PRIVATE 
        ${blst_SOURCE_DIR}/src
        ${blst_SOURCE_DIR}/bindings
    )
    if(MSVC)
        set_source_files_properties(
            "${blst_SOURCE_DIR}/src/server.c"
            PROPERTIES COMPILE_OPTIONS "/std:c11;/W1;/wd4146;/wd4334;/wd4245;/wd4267;/wd4028"
        )
    else()
        target_compile_options(blst PRIVATE -std=c11 -w)
    endif()
    
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "arm")
        target_compile_definitions(blst PRIVATE __ARM_ARCH=7)
    endif()
endif()

message(STATUS "Fetching micro-ecc....")
FetchContent_Declare(
    micro_ecc 
    GIT_REPOSITORY https://github.com/kmackay/micro-ecc.git
    GIT_TAG        master   
)

FetchContent_GetProperties(micro_ecc)
if(NOT micro_ecc_POPULATED)
    FetchContent_Populate(micro_ecc)
endif()
FetchContent_GetProperties(micro_ecc SOURCE_DIR uECC_SOURCE_DIR)

message(STATUS "Fetching PicoSHA2")
FetchContent_Declare(
    picosha2
    GIT_REPOSITORY https://github.com/okdshin/PicoSHA2.git
    GIT_TAG        master
)

FetchContent_GetProperties(picosha2)
if(NOT picosha2_POPULATED)
    FetchContent_Populate(picosha2)
endif()
FetchContent_GetProperties(picosha2 SOURCE_DIR picosha2_SOURCE_DIR)

message(STATUS "Fetching tiny-AES-c...")
FetchContent_Declare(
    tiny_aes
    GIT_REPOSITORY https://github.com/kokke/tiny-AES-c.git
    GIT_TAG        master
)

FetchContent_GetProperties(tiny_aes)
if(NOT tiny_aes_POPULATED)
    FetchContent_Populate(tiny_aes)
endif()
FetchContent_GetProperties(tiny_aes SOURCE_DIR aes_SOURCE_DIR)

add_subdirectory(src)

if(ESL_BUILD_EXAMPLES) #test first
    add_subdirectory(examples)
endif()

if(ESL_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# ===== Install: CMake package config =====
configure_package_config_file(
    cmake/EslConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/EslConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/esl
)

write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/EslConfigVersion.cmake
    VERSION       ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/EslConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/EslConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/esl
)