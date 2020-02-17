cmake_minimum_required(VERSION 3.5)

project(ethash)

set(EOSIO_WASM_OLD_BEHAVIOR "Off")
find_package(eosio.cdt)
include(EosioWasmToolchain)

add_library(ethash STATIC
        lib/ethash/ethash.cpp
        )

add_library(keccak STATIC
        lib/keccak/keccak.c lib/keccak/keccakf1600.c lib/keccak/keccakf800.c)

target_include_directories(ethash
        PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include/
        PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/ethash/
        )

target_include_directories(keccak
        PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include/
        PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/keccak/
        )

target_compile_definitions(ethash PRIVATE HAVE_CONFIG_H=1)
