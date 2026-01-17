if(ESL_BUILD_SHARED)
    add_library(esl SHARED)
else()
    add_library(esl STATIC)
endif()

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

target_include_directories(esl 
    PUBLIC 
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${uECC_SOURCE_DIR}
    ${picosha2_SOURCE_DIR}
    ${aes_SOURCE_DIR}
)

target_compile_definitions(esl PRIVATE CBC=1 CTR=0 ECB=0)
target_link_libraries(esl PRIVATE mcl::mcl )

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


include(GNUInstallDirs)

install(TARGETS esl
    EXPORT eslTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(DIRECTORY ${CMAKE_SOURCE_DIR}/include/esl
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

include(CMakePackageConfigHelpers)

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/eslConfigVersion.cmake"
    VERSION 0.9.5
    COMPATIBILITY AnyNewerVersion
)

file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/eslConfig.cmake"
    "include(CMakeFindDependencyMacro)\n"
    "find_dependency(mcl)\n" 
    "include(\"\${CMAKE_CURRENT_LIST_DIR}/eslTargets.cmake\")\n"
)

file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/mclConfig.cmake"
    "include(\"\${CMAKE_CURRENT_LIST_DIR}/mclTargets.cmake\")\n"
)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/mclConfig.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/mcl
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/eslConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/eslConfigVersion.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/esl
)

install(EXPORT eslTargets
    FILE eslTargets.cmake
    NAMESPACE esl::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/esl
)