# codec, tl and fee harnesses (docs/codec.md). Their fixtures run under conformance-vectors; this part
# links the TL libraries the tl harness needs and adds the cross-checks of the migrated families against
# the drivers and frozen files they came from.
target_link_libraries(conformance-ref PRIVATE tl-utils tl-lite-utils tl_api tl_lite_api tl_toslib_api)

# test-tl-cli-fixtures is defined after this directory, unconditionally; the emulator drivers exist whenever
# this directory is built.
if (TARGET test-varuint-codec AND TARGET test-gas-purchase AND TARGET test-storage-encoding)
  add_test(NAME conformance-codec-migration
    COMMAND ${Python3_EXECUTABLE} -B ${CONFORMANCE_DIR}/migrate/codec.py check
      --vectors ${CONFORMANCE_DIR}/vectors
      --varuint-driver $<TARGET_FILE:test-varuint-codec>
      --gas-driver $<TARGET_FILE:test-gas-purchase>
      --storage-encoding-driver $<TARGET_FILE:test-storage-encoding>
      --tl-driver $<TARGET_FILE:test-tl-cli-fixtures>
      --work-dir ${CMAKE_CURRENT_BINARY_DIR}/codec-migration)
  set_tests_properties(conformance-codec-migration PROPERTIES LABELS "conformance" TIMEOUT 900)
endif()
