cmake_minimum_required(VERSION 3.5)

project(intx)

set(EOSIO_WASM_OLD_BEHAVIOR "Off")
find_package(eosio.cdt)
include(EosioWasmToolchain)

add_library(intx STATIC
        lib/intx/div.cpp
        include/intx/intx.hpp
        include/intx/int128.hpp
        )

target_include_directories(intx
        PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/intx/
        )