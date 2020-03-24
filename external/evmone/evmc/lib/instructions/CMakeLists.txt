# EVMC: Ethereum Client-VM Connector API.
# Copyright 2018-2019 The EVMC Authors.
# Licensed under the Apache License, Version 2.0.

include_directories(
        ${CMAKE_SOURCE_DIR}/../../include
        ${CMAKE_SOURCE_DIR}/evmc/include
)

add_library(
    instructions STATIC
    instruction_metrics.c
    instruction_names.c
)

add_library(evmc::instructions ALIAS instructions)
target_include_directories(instructions PUBLIC
    $<BUILD_INTERFACE:${include_dir}>$<INSTALL_INTERFACE:include>
)

if(EVMC_INSTALL)
    install(TARGETS instructions EXPORT evmcTargets DESTINATION ${CMAKE_INSTALL_LIBDIR})
endif()
