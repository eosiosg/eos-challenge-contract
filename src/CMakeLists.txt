cmake_minimum_required(VERSION 3.5)

project(test_contract)

set(EOSIO_WASM_OLD_BEHAVIOR "Off")
find_package(eosio.cdt)

add_subdirectory(secp256k1-eosio)
link_libraries(secp256k1)
add_subdirectory(ethash)
link_libraries(ethash)
link_libraries(keccak)
add_subdirectory(intx)
link_libraries(intx)
add_subdirectory(evmone)
link_libraries(evmone)

add_contract( test_contract test_contract test_contract.cpp RLP/rlp.cpp)
target_include_directories( test_contract PUBLIC ${CMAKE_SOURCE_DIR}/../include )
target_include_directories( test_contract PUBLIC ${CMAKE_SOURCE_DIR}/intx/include/intx)
target_include_directories( test_contract PUBLIC
        ${CMAKE_SOURCE_DIR}/evmone/lib
        ${CMAKE_SOURCE_DIR}/evmone/include
        ${CMAKE_SOURCE_DIR}/RLP
        ${CMAKE_SOURCE_DIR}/RLP/src
        )
