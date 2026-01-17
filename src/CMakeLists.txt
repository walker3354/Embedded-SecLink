if(ESL_BUILD_SHARED)
    add_library(esl SHARED)
else()
    add_library(esl STATIC)
endif()

add_library(esl::esl ALIAS esl)

target_sources(esl 
    PRIVATE
    ${aes_SOURCE_DIR}/aes.c
    ${uECC_SOURCE_DIR}/uECC.c 

    crypto/BlsCore.cpp
    crypto/EccCore.cpp
    crypto/AesCore.cpp

    utils/Random.cpp
    utils/Stopwatch.cpp
    utils/TimeUtils.cpp
    utils/HashTree.cpp
)

get_filename_component(ESL_REAL_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../include" ABSOLUTE)

target_include_directories(esl 
    PUBLIC 
    $<BUILD_INTERFACE:${ESL_REAL_INCLUDE_DIR}>
    $<INSTALL_INTERFACE:include>
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${uECC_SOURCE_DIR}
    ${picosha2_SOURCE_DIR}
    ${aes_SOURCE_DIR}
)

target_compile_definitions(esl PRIVATE CBC=1 CTR=0 ECB=0)
target_link_libraries(esl PUBLIC mcl::mcl )

if(ESL_STRICT_MODE)
    if(MSVC)
        target_compile_options(esl PRIVATE /W4 /WX)
    else()
        target_compile_options(esl PRIVATE -Wall -Wextra -Wpedantic -Werror)
    endif()
endif()

if(MSVC)
    set_source_files_properties(
        ${uECC_SOURCE_DIR}/uECC.c
        ${aes_SOURCE_DIR}/aes.c
        PROPERTIES COMPILE_OPTIONS "/W1;/WX-"
    )
else()
    set_source_files_properties(
        ${uECC_SOURCE_DIR}/uECC.c
        ${aes_SOURCE_DIR}/aes.c
        PROPERTIES COMPILE_OPTIONS "-w"
    )
endif()
