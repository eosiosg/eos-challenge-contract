project(test_contract)

set(EOSIO_WASM_OLD_BEHAVIOR "Off")
find_package(eosio.cdt)

add_subdirectory(secp256k1)
link_libraries(secp256k1)
add_subdirectory(ethash)
link_libraries(ethash)
link_libraries(keccak)
add_subdirectory(calculate)
link_libraries(calculate)

add_contract( test_contract test_contract test_contract.cpp )
target_include_directories( test_contract PUBLIC ${CMAKE_SOURCE_DIR}/../include )
