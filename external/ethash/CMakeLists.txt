cmake_minimum_required(VERSION 3.5)

project(ethash)

set(EOSIO_WASM_OLD_BEHAVIOR "Off")
find_package(eosio.cdt)
include(EosioWasmToolchain)

add_library(ethash STATIC
        lib/ethash/bit_manipulation.h
        lib/ethash/builtins.h
        lib/ethash/endianness.hpp
        include/ethash/ethash.h
        include/ethash/ethash.hpp
        lib/ethash/ethash-internal.hpp
        lib/ethash/ethash.cpp
        include/ethash/hash_types.h
#        lib/ethash/managed.cpp
        lib/ethash/kiss99.hpp
        lib/ethash/primes.h
        lib/ethash/primes.c
        include/ethash/progpow.hpp
        lib/ethash/progpow.cpp

        include/ethash/keccak.h
        include/ethash/keccak.hpp
        )

add_library(keccak STATIC
        include/ethash/keccak.h
        include/ethash/keccak.hpp
        lib/keccak/keccak.c
        lib/keccak/keccakf1600.c
        lib/keccak/keccakf800.c)

target_link_libraries(ethash PUBLIC keccak)

target_include_directories(ethash
        PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include/
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/ethash/
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/keccak/
        )

target_include_directories(keccak
        PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include/
        PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/keccak/
        )

target_compile_definitions(ethash PRIVATE HAVE_CONFIG_H=1)

