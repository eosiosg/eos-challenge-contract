include(ExternalProject)

set(prefix "${CMAKE_BINARY_DIR}/eos_evm/deps")
set(ETHASH_LIBRARY "${prefix}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}ethash${CMAKE_STATIC_LIBRARY_SUFFIX}")
set(KECCAK_LIBRARY "${prefix}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}keccak${CMAKE_STATIC_LIBRARY_SUFFIX}")
set(ETHASH_INCLUDE_DIR "${prefix}/include/ethash")

ExternalProject_Add(
        ethash
        PREFIX "${prefix}"
        GIT_REPOSITORY https://github.com/chfast/ethash.git
        GIT_TAG v0.5.1
        PATCH_COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${CMAKE_CURRENT_LIST_DIR}/CMakeLists.txt <SOURCE_DIR>
        CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${ETHASH_LIBRARY}
            ${_only_release_configuration}
        INSTALL_COMMAND  ${CMAKE_COMMAND} -E copy ${CMAKE_STATIC_LIBRARY_PREFIX}ethash${CMAKE_STATIC_LIBRARY_SUFFIX} ${ETHASH_LIBRARY}
        COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_STATIC_LIBRARY_PREFIX}keccak${CMAKE_STATIC_LIBRARY_SUFFIX} ${KECCAK_LIBRARY}
        COMMAND ${CMAKE_COMMAND} -E copy_directory <SOURCE_DIR>/include/ethash ${ETHASH_INCLUDE_DIR}
        LOG_INSTALL 1
        BUILD_BYPRODUCTS "${ETHASH_LIBRARY}"
)