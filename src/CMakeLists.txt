if(ESL_BUILD_SHARED)
    add_library(esl SHARED)
else()
    add_library(esl STATIC)
endif()

target_sources(esl PRIVATE esl_core.cpp)

target_include_directories(esl PUBLIC 
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(esl PRIVATE OpenSSL::Crypto)

if(ESL_STRICT_MODE)
    if(MSVC)
        target_compile_options(esl PRIVATE /W4 /WX)
    else()
        target_compile_options(esl PRIVATE -Wall -Wextra -Wpedantic -Werror)
    endif()
endif()