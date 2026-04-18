# silkworm-core: Ethereum execution engine types, state, and EVM wrapper.
# Original source: ~/s/silkworm/core/ (The Silkworm Authors, Apache-2.0).
# Adapted CMakeLists.txt for the host-chain build system.
#
# This builds only the execution-critical subset:
#   types, rlp, state, execution, protocol, chain config, common, crypto, trie
# Test files (*_test.cpp), benchmarks, and genesis chain data are excluded.

# --- Collect source files (no tests, no benchmarks, no per-chain genesis) ---
set(SILKWORM_CORE_SRC
  # common
  common/assert.cpp
  common/endian.cpp
  common/util.cpp
  # crypto
  crypto/ecdsa.c
  crypto/secp256k1n.cpp
  # rlp
  rlp/decode.cpp
  rlp/encode.cpp
  # types
  types/account.cpp
  types/address.cpp
  types/block.cpp
  types/bloom.cpp
  types/eip_7685_requests.cpp
  types/evmc_bytes32.cpp
  types/log.cpp
  types/receipt.cpp
  types/transaction.cpp
  types/withdrawal.cpp
  types/y_parity_and_chain_id.cpp
  # chain (JSON serialization guarded by SILKWORM_NO_JSON)
  chain/config.cpp
  # protocol (ethash_config, bor/config, bor/span, blockchain excluded — need JSON)
  protocol/intrinsic_gas.cpp
  protocol/rule_set.cpp
  protocol/validation.cpp
  protocol/ethash_rule_set.cpp
  protocol/merge_rule_set.cpp
  protocol/bor_rule_set.cpp
  protocol/bor/config.cpp
  protocol/bor/span.cpp
  # chain
  chain/dao.cpp
  # state
  state/delta.cpp
  state/in_memory_state.cpp
  state/intra_block_state.cpp
  # execution
  execution/evm.cpp
  execution/processor.cpp
  execution/precompile.cpp
  execution/call_tracer.cpp
  # trie (needed by in_memory_state)
  trie/hash_builder.cpp
  trie/nibbles.cpp
  trie/node.cpp
  trie/prefix_set.cpp
)

add_library(silkworm_core STATIC ${SILKWORM_CORE_SRC})

# Include paths:
#   - parent of silkworm/ so that <silkworm/core/...> resolves
#   - compat headers for magic_enum, GSL, tl-expected, nlohmann_json
target_include_directories(silkworm_core
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../..          # resolves <silkworm/core/...>
    ${CMAKE_SOURCE_DIR}/third-party/compat     # magic_enum.hpp, gsl/, tl/, nlohmann/
)

# Public dependencies (consumers also need these headers)
target_link_libraries(silkworm_core
  PUBLIC
    evmone       # includes evmc and intx::intx transitively
    ethash::ethash
)

# secp256k1 for sender recovery.
# The host chain builds secp256k1 as a custom target; create an imported lib.
if(NOT TARGET secp256k1::secp256k1)
  add_library(secp256k1_imported STATIC IMPORTED GLOBAL)
  set_target_properties(secp256k1_imported PROPERTIES
    IMPORTED_LOCATION "${SECP256K1_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${SECP256K1_INCLUDE_DIR}"
  )
  if(TARGET secp256k1)
    add_dependencies(secp256k1_imported secp256k1)
  endif()
  add_library(secp256k1::secp256k1 ALIAS secp256k1_imported)
endif()
target_link_libraries(silkworm_core PRIVATE secp256k1_imported)
target_include_directories(silkworm_core PRIVATE ${SECP256K1_INCLUDE_DIR})

# libff for alt_bn128 pairing + GMP for modexp
if(TARGET ff)
  target_link_libraries(silkworm_core PRIVATE ff)
  message(STATUS "silkworm_core: libff + GMP enabled (full precompile support)")
else()
  target_compile_definitions(silkworm_core PRIVATE SILKWORM_NO_LIBFF=1)
  message(STATUS "silkworm_core: libff not available (bn254 pairing/modexp stubbed)")
endif()

# nlohmann_json not available — guard JSON serialization.
target_compile_definitions(silkworm_core PRIVATE
  SILKWORM_NO_JSON=1
)

# OpenSSL libcrypto for EIP-7951 secp256r1 (P-256) ECDSA verify.
find_package(OpenSSL REQUIRED)
target_link_libraries(silkworm_core PRIVATE OpenSSL::Crypto)

if(MSVC)
  target_compile_options(silkworm_core PRIVATE /w)
else()
  target_compile_options(silkworm_core PRIVATE
    -Wno-sign-conversion
    -Wno-conversion
    -Wno-unused-parameter
    -Wno-sign-compare
    -Wno-missing-field-initializers
    -Wno-unused-variable
    -Wno-deprecated-declarations
  )
endif()
