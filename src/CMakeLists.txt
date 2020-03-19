cmake_minimum_required(VERSION 3.5)

project(eos_evm)

set(EOSIO_WASM_OLD_BEHAVIOR "Off")
find_package(eosio.cdt)

add_subdirectory(${CMAKE_BINARY_DIR}/deps/src/ethash ${CMAKE_BINARY_DIR}/deps/src/ethash)
add_subdirectory(${CMAKE_BINARY_DIR}/deps/src/intx ${CMAKE_BINARY_DIR}/deps/src/intx)

link_libraries(ethash)
link_libraries(keccak)
link_libraries(intx)
link_libraries(evmone)

link_directories(${CMAKE_BINARY_DIR}/deps/lib)
add_contract( eos_evm eos_evm eos_evm.cpp RLP/rlp.cpp ecc/uECC.c)

target_include_directories( eos_evm PUBLIC
        ${CMAKE_SOURCE_DIR}/RLP
        ${CMAKE_SOURCE_DIR}/../include
        ${CMAKE_BINARY_DIR}/deps/include/intx
        ${CMAKE_BINARY_DIR}/deps/include
        )
