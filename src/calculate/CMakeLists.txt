
project(calculate)

cmake_minimum_required(VERSION 3.5)

set(EOSIO_WASM_OLD_BEHAVIOR "Off")
find_package(eosio.cdt)
include(EosioWasmToolchain)

add_library(calculate STATIC
        add.cpp
        )

target_include_directories( calculate PUBLIC ${CMAKE_SOURCE_DIR})