# EVM third-party: evmone - Ethereum Virtual Machine implementation
# Adapted from Silkworm (~/s/third_party/evmone/CMakeLists.txt) for TOS build system.
# Source: https://github.com/erigontech/evmone
# SPDX-License-Identifier: Apache-2.0

# --- evmc (Ethereum Client-VM Connector API) ---
set(EVMC_INSTALL OFF CACHE BOOL "" FORCE)
set(EVMC_TESTING OFF CACHE BOOL "" FORCE)
set(EVMC_TOOLS OFF CACHE BOOL "" FORCE)
set(EVMC_EXAMPLES OFF CACHE BOOL "" FORCE)
add_subdirectory(evmone/evmc)

# --- blst::blst compatibility target ---
# TOS builds blst as a custom target with BLST_LIB / BLST_INCLUDE_DIR.
# evmone expects a blst::blst imported target. Bridge them here.
if(NOT TARGET blst::blst)
  add_library(blst::blst STATIC IMPORTED GLOBAL)
  set_target_properties(blst::blst PROPERTIES
    IMPORTED_LOCATION "${BLST_LIB}"
    INTERFACE_INCLUDE_DIRECTORIES "${BLST_INCLUDE_DIR}"
  )
  if(TARGET blst)
    add_dependencies(blst::blst blst)
  endif()
endif()

# --- evmone library ---
add_library(
  evmone
  evmone/lib/evmone/advanced_analysis.cpp
  evmone/lib/evmone/advanced_analysis.hpp
  evmone/lib/evmone/advanced_execution.cpp
  evmone/lib/evmone/advanced_execution.hpp
  evmone/lib/evmone/advanced_instructions.cpp
  evmone/lib/evmone/baseline_analysis.cpp
  evmone/lib/evmone/baseline_execution.cpp
  evmone/lib/evmone/baseline_instruction_table.cpp
  evmone/lib/evmone/baseline_instruction_table.hpp
  evmone/lib/evmone/baseline.hpp
  evmone/lib/evmone/constants.hpp
  evmone/lib/evmone/delegation.cpp
  evmone/lib/evmone/delegation.hpp
  evmone/lib/evmone/eof.cpp
  evmone/lib/evmone/eof.hpp
  evmone/lib/evmone/execution_state.hpp
  evmone/lib/evmone/instructions_calls.cpp
  evmone/lib/evmone/instructions_opcodes.hpp
  evmone/lib/evmone/instructions_storage.cpp
  evmone/lib/evmone/instructions_traits.hpp
  evmone/lib/evmone/instructions_xmacro.hpp
  evmone/lib/evmone/instructions.hpp
  evmone/lib/evmone/tracing.cpp
  evmone/lib/evmone/tracing.hpp
  evmone/lib/evmone/vm.cpp
  evmone/lib/evmone/vm.hpp
  evmone/lib/evmone_precompiles/blake2b.cpp
  evmone/lib/evmone_precompiles/ripemd160.cpp
  evmone/lib/evmone_precompiles/sha256.cpp
  evmone/lib/evmone_precompiles/kzg.cpp
  evmone/lib/evmone_precompiles/bn254.cpp
  evmone/lib/evmone_precompiles/secp256k1.cpp
  evmone/lib/evmone_precompiles/bls.cpp
  evmone/test/state/host.cpp
  evmone/test/state/precompiles.cpp
  evmone/test/state/state.cpp
)

set_source_files_properties(evmone/lib/evmone/vm.cpp PROPERTIES COMPILE_DEFINITIONS PROJECT_VERSION="0.11.0")

target_include_directories(
  evmone
  PUBLIC evmone/include evmone/lib
  INTERFACE .
  PRIVATE
    evmone/test           # for utils/stdx/utility.hpp
    ${CMAKE_SOURCE_DIR}/third-party            # for <silkworm/core/...> used by evmone test/state
    ${CMAKE_SOURCE_DIR}/third-party/compat    # for hash_maps fallback deps
)

target_link_libraries(
  evmone
  PUBLIC evmc intx::intx blst::blst
  PRIVATE ethash::keccak
)

if(MSVC)
  target_compile_options(evmone PRIVATE /EHsc /w)
else()
  target_compile_options(
    evmone
    PRIVATE -fno-exceptions
            $<$<CXX_COMPILER_ID:GNU>:-Wno-attributes>
            $<$<CXX_COMPILER_ID:Clang,AppleClang>:-Wno-unknown-attributes>
            $<$<CXX_COMPILER_ID:Clang,AppleClang>:-Wno-deprecated-literal-operator>
  )
endif()
