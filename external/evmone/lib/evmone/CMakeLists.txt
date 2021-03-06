# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2019 Pawel Bylica.
# Licensed under the Apache License, Version 2.0.

#include(LibraryTools)

set(EOSIO_WASM_OLD_BEHAVIOR "Off")
find_package(eosio.cdt)
include(EosioWasmToolchain)

#hunter_add_package(intx)
#find_package(intx CONFIG REQUIRED)


include_directories(
        ${CMAKE_SOURCE_DIR}/../../include
        ${CMAKE_SOURCE_DIR}/evmc/include
)

add_library(evmone
    ${include_dir}/evmone/evmone.h
    analysis.cpp
    analysis.hpp
    evmone.cpp
    execution.cpp
    execution.hpp
    instructions.cpp
    limits.hpp
    opcodes_helpers.h
)
target_link_libraries(evmone PUBLIC evmc::evmc PRIVATE intx keccak)
target_include_directories(evmone PUBLIC
    $<BUILD_INTERFACE:${include_dir}>$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)


set_target_properties(
    evmone
    PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_SOVERSION}
)

if(NOT SANITIZE)
    # On Linux, check if all symbols in evmone are resolved during linking.
    target_link_options(evmone PRIVATE $<$<PLATFORM_ID:Linux>:LINKER:--no-undefined>)
endif()

set_source_files_properties(evmone.cpp PROPERTIES COMPILE_DEFINITIONS PROJECT_VERSION="\\"${PROJECT_VERSION}\\"")

#add_standalone_library(evmone)
