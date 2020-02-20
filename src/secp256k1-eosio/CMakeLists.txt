#
## include_directories (${CMAKE_SOURCE_DIR}/../secp256k1)
#
#add_compile_definitions(HAVE_CONFIG_H)
#
#add_library(secp256k1 src/secp256k1.c)
#target_include_directories( secp256k1 PUBLIC ${CMAKE_SOURCE_DIR}/../src/secp256k1 )
#target_include_directories( secp256k1 PRIVATE ${CMAKE_SOURCE_DIR}/../src/secp256k1/src )

cmake_minimum_required(VERSION 3.5)

project(secp256k1)

set(EOSIO_WASM_OLD_BEHAVIOR "Off")
find_package(eosio.cdt)
include(EosioWasmToolchain)

add_library(secp256k1 STATIC
        src/secp256k1.c
        )

target_include_directories(secp256k1
        PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/src/modules/ecdh
        ${CMAKE_CURRENT_SOURCE_DIR}/src/modules/recovery
        )

target_compile_definitions(secp256k1 PRIVATE HAVE_CONFIG_H=1)
