cmake_minimum_required(VERSION 3.5)

project(secp256k1)

set(EOSIO_WASM_OLD_BEHAVIOR "Off")
find_package(eosio.cdt)
include(EosioWasmToolchain)

add_library(secp256k1 STATIC
  upstream/src/secp256k1.c
)

target_include_directories(secp256k1
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/upstream/
        ${CMAKE_CURRENT_SOURCE_DIR}/upstream/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/upstream/src
        ${CMAKE_CURRENT_SOURCE_DIR}/upstream/src/modules/aggsig
        ${CMAKE_CURRENT_SOURCE_DIR}/upstream/src/modules/bulletproofs
        ${CMAKE_CURRENT_SOURCE_DIR}/upstream/src/modules/commitment
        ${CMAKE_CURRENT_SOURCE_DIR}/upstream/src/modules/ecdh
        ${CMAKE_CURRENT_SOURCE_DIR}/upstream/src/modules/generator
        ${CMAKE_CURRENT_SOURCE_DIR}/upstream/src/modules/rangeproof
        ${CMAKE_CURRENT_SOURCE_DIR}/upstream/src/modules/recovery
        ${CMAKE_CURRENT_SOURCE_DIR}/upstream/src/modules/schnorrsig
        ${CMAKE_CURRENT_SOURCE_DIR}/upstream/src/modules/surjection
        ${CMAKE_CURRENT_SOURCE_DIR}/upstream/src/modules/whitelist
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_compile_definitions(secp256k1 PRIVATE HAVE_CONFIG_H=1)