include(ExternalProject)

set(prefix "${CMAKE_BINARY_DIR}/eos_evm/deps")
set(EVMONE_LIBRARY "${prefix}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}evmone${CMAKE_STATIC_LIBRARY_SUFFIX}")
set(EVMONE_INCLUDE_DIR "${prefix}/include/evmone")
set(EVMC_INCLUDE_DIR "${prefix}/include/evmc")

ExternalProject_Add(
        evmone
        PREFIX "${prefix}"
        DOWNLOAD_NAME evmone.tar.gz
        DOWNLOAD_NO_PROGRESS 1
        GIT_REPOSITORY https://github.com/ethereum/evmone.git
        GIT_TAG v0.4.0
        GIT_PROGRESS 0
        GIT_SUBMODULES evmc
        PATCH_COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_LIST_DIR}/CMakeLists.txt <SOURCE_DIR>
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_LIST_DIR}/lib/evmone/CMakeLists.txt <SOURCE_DIR>/lib/evmone/CMakeLists.txt
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_LIST_DIR}/evmc/CMakeLists.txt <SOURCE_DIR>/evmc/CMakeLists.txt
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_LIST_DIR}/evmc/lib/CMakeLists.txt <SOURCE_DIR>/evmc/lib/CMakeLists.txt
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_LIST_DIR}/evmc/lib/instructions/CMakeLists.txt <SOURCE_DIR>/evmc/lib/instructions/CMakeLists.txt
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_LIST_DIR}/lib/evmone/instructions.cpp <SOURCE_DIR>/lib/evmone/instructions.cpp
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_LIST_DIR}/lib/evmone/analysis.hpp <SOURCE_DIR>/lib/evmone/analysis.hpp
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_LIST_DIR}/lib/evmone/analysis.cpp <SOURCE_DIR>/lib/evmone/analysis.cpp
        CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${EVMONE_LIBRARY}
            ${_only_release_configuration}
        INSTALL_COMMAND  ${CMAKE_COMMAND} -E copy lib/evmone/${CMAKE_STATIC_LIBRARY_PREFIX}evmone${CMAKE_STATIC_LIBRARY_SUFFIX} ${EVMONE_LIBRARY}
        COMMAND ${CMAKE_COMMAND} -E copy_directory <SOURCE_DIR>/include/evmone ${EVMONE_INCLUDE_DIR}
        COMMAND ${CMAKE_COMMAND} -E copy_if_different <SOURCE_DIR>/lib/evmone/execution.hpp ${EVMONE_INCLUDE_DIR}
        COMMAND ${CMAKE_COMMAND} -E copy_directory <SOURCE_DIR>/evmc/include/evmc ${EVMC_INCLUDE_DIR}

        LOG_INSTALL 1
        BUILD_BYPRODUCTS "${EVMONE_LIBRARY}"
        BUILD_ALWAYS 1
        DEPENDS intx ethash
)
