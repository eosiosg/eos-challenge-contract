include(ExternalProject)

set(prefix "${CMAKE_BINARY_DIR}/eos_evm/deps")
set(INTX_LIBRARY "${prefix}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}intx${CMAKE_STATIC_LIBRARY_SUFFIX}")
set(INTX_INCLUDE_DIR "${prefix}/include/intx")

ExternalProject_Add(
        intx
        PREFIX "${prefix}"
        DOWNLOAD_NAME intx.tar.gz
        DOWNLOAD_NO_PROGRESS 1
        GIT_REPOSITORY https://github.com/chfast/intx.git
#        GIT_TAG b7d53c7ba890bbdf385290e1990da58e046b1719
        GIT_TAG v0.4.0
        PATCH_COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${CMAKE_CURRENT_LIST_DIR}/CMakeLists.txt <SOURCE_DIR>
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_LIST_DIR}/include/int128.hpp <SOURCE_DIR>/include/intx
        CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${INTX_LIBRARY}
            ${_only_release_configuration}
        INSTALL_COMMAND  ${CMAKE_COMMAND} -E copy ${CMAKE_STATIC_LIBRARY_PREFIX}intx${CMAKE_STATIC_LIBRARY_SUFFIX} ${INTX_LIBRARY}
        COMMAND ${CMAKE_COMMAND} -E copy_directory <SOURCE_DIR>/include/intx ${INTX_INCLUDE_DIR}
        LOG_INSTALL 1
        BUILD_BYPRODUCTS "${INTX_LIBRARY}"
)
