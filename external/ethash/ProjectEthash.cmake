include(ExternalProject)

set(prefix "${CMAKE_BINARY_DIR}/eos_evm/deps")
set(ETHASH_LIBRARY "${prefix}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}ethash${CMAKE_STATIC_LIBRARY_SUFFIX}")
set(KECCAK_LIBRARY "${prefix}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}keccak${CMAKE_STATIC_LIBRARY_SUFFIX}")
set(ETHASH_INCLUDE_DIR "${prefix}/include")

ExternalProject_Add(
        ethash
        PREFIX "${prefix}"
        DOWNLOAD_NAME ethash.tar.gz
        DOWNLOAD_NO_PROGRESS 1
        URL https://github.com/chfast/ethash/archive/v0.4.4.tar.gz
        URL_HASH SHA256=191b6b324a3af734b801c08499e109a2bdc9ac9fac5b82b98cd7541b1ed4ef11
        PATCH_COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${CMAKE_CURRENT_LIST_DIR}/CMakeLists.txt <SOURCE_DIR>
        CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${ETHASH_LIBRARY}
            ${_only_release_configuration}
        INSTALL_COMMAND  ${CMAKE_COMMAND} -E copy ${CMAKE_STATIC_LIBRARY_PREFIX}ethash${CMAKE_STATIC_LIBRARY_SUFFIX} ${ETHASH_LIBRARY}
        COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_STATIC_LIBRARY_PREFIX}keccak${CMAKE_STATIC_LIBRARY_SUFFIX} ${KECCAK_LIBRARY}
        COMMAND ${CMAKE_COMMAND} -E copy_directory <SOURCE_DIR>/include ${ETHASH_INCLUDE_DIR}
        LOG_INSTALL 1
        BUILD_BYPRODUCTS "${ETHASH_LIBRARY}"
)

#add_library(Ethash STATIC IMPORTED)
#file(MAKE_DIRECTORY "${ETHASH_INCLUDE_DIR}")  # Must exist.
#set_property(TARGET Ethash PROPERTY IMPORTED_CONFIGURATIONS Release)
#set_property(TARGET Ethash PROPERTY IMPORTED_LOCATION_RELEASE "${ETHASH_LIBRARY}")
#set_property(TARGET Ethash PROPERTY INTERFACE_INCLUDE_DIRECTORIES "${ETHASH_INCLUDE_DIR}")
#add_dependencies(Ethash ethash)