cmake_minimum_required(VERSION 3.5)

project(eos_evm)

set(EOSIO_WASM_OLD_BEHAVIOR "Off")
find_package(eosio.cdt)

add_subdirectory(${CMAKE_BINARY_DIR}/deps/src/ethash ${CMAKE_BINARY_DIR}/deps/src/ethash)
#add_subdirectory(ethash)
#link_libraries(ethash)
#link_libraries(keccak)
add_subdirectory(intx)
link_libraries(intx)
add_subdirectory(evmone)
link_libraries(evmone)


add_contract( eos_evm eos_evm eos_evm.cpp RLP/rlp.cpp ecc/uECC.c)
target_include_directories( eos_evm PUBLIC ${CMAKE_SOURCE_DIR}/../include )
target_include_directories( eos_evm PUBLIC ${CMAKE_SOURCE_DIR}/intx/include/intx)
target_include_directories( eos_evm PUBLIC
        ${CMAKE_SOURCE_DIR}/evmone/lib
        ${CMAKE_SOURCE_DIR}/evmone/include
        ${CMAKE_SOURCE_DIR}/RLP
        ${CMAKE_SOURCE_DIR}/RLP/src
        )
