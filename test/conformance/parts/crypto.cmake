# crypto harness (ref/harness-crypto.cpp): the verifiers, hashes and consensus-identity encodings it
# calls live outside the emulator, so the reference library links them directly.
target_link_libraries(conformance-ref PRIVATE tos_block tos_crypto tos_mldsa44 tos_falcon512 tos_slhdsa128s
  tos_lms_fee tos_pq_consensus tl_api tl_lite_api tl-utils tl-lite-utils)
target_include_directories(conformance-ref PRIVATE ${CMAKE_SOURCE_DIR} ${CMAKE_SOURCE_DIR}/crypto)
# Visibility of the shared library is set in ../CMakeLists.txt: it exports only conformance_* symbols.

# The C++ generators whose frozen output the crypto fixtures were migrated from must keep agreeing
# with those fixtures row for row (migrate/crypto_generators.py).
if (TARGET pq-bytes-vectors-gen AND TARGET config43-vectors-gen AND TARGET authorisation-preimage-vectors-gen
    AND TARGET descriptor-verdict-vectors-gen AND TARGET validator-session-vectors-gen)
  add_test(NAME conformance-crypto-generators
    COMMAND ${Python3_EXECUTABLE} -B ${CONFORMANCE_DIR}/migrate/crypto_generators.py check
      --source-dir ${CMAKE_SOURCE_DIR}
      --vectors ${CONFORMANCE_DIR}/vectors/crypto/fixtures
      --pq-bytes-gen $<TARGET_FILE:pq-bytes-vectors-gen>
      --config43-gen $<TARGET_FILE:config43-vectors-gen>
      --preimage-gen $<TARGET_FILE:authorisation-preimage-vectors-gen>
      --descriptor-gen $<TARGET_FILE:descriptor-verdict-vectors-gen>
      --session-gen $<TARGET_FILE:validator-session-vectors-gen>)
  set_tests_properties(conformance-crypto-generators PROPERTIES LABELS "conformance" TIMEOUT 300)
endif()
