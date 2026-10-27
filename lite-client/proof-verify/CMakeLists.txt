# Shared proof verification core and its installed command-line front end.
# The engine accepts borrowed in-memory material and has no transport/file API.
add_library(proof-verify-engine STATIC proof-verify.cpp proof-verify.h embedded.cpp embedded.h
  wallet-transaction.cpp wallet-transaction.h self-pay-simulation-context.cpp self-pay-simulation-context.h simulation-config.cpp simulation-config.h simulation-account.cpp simulation-account.h self-pay-simulation.cpp self-pay-simulation.h proof-self-pay-simulation.cpp)
target_include_directories(proof-verify-engine PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
  $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}>)
target_link_libraries(proof-verify-engine PUBLIC lite-client-proof-common tos_block smc-envelope tl_api tl_lite_api
  tl-lite-utils tdutils emulator_static)

# Swift/JNI consumers load the C ABI without linking desktop acquisition code.
add_library(tos-proof-embedded SHARED EXCLUDE_FROM_ALL embedded.cpp persisted.cpp persisted.h)
target_link_libraries(tos-proof-embedded PRIVATE proof-verify-engine)
set_target_properties(tos-proof-embedded PROPERTIES OUTPUT_NAME tosproofverify)
if(ANDROID)
  target_sources(tos-proof-embedded PRIVATE android-jni.cpp)
  target_link_options(tos-proof-embedded PRIVATE "-Wl,-z,max-page-size=16384")
endif()

add_library(proof-material-acquisition STATIC acquisition.cpp material.h)
target_link_libraries(proof-material-acquisition PUBLIC proof-verify-engine)
target_sources(tos-proof-embedded PRIVATE acquisition-c.cpp acquisition.h)
target_link_libraries(tos-proof-embedded PRIVATE proof-material-acquisition)

# Desktop acquisition/storage adapters remain outside the embedded engine.
add_library(proof-verify-core STATIC material.cpp material.h)
target_link_libraries(proof-verify-core PUBLIC proof-material-acquisition lite-client-common tdactor)

add_executable(tos-proof-verify main.cpp)
target_link_libraries(tos-proof-verify PRIVATE proof-verify-core)

install(TARGETS tos-proof-verify RUNTIME DESTINATION bin)

add_executable(test-proof-verify-embedded ../../test/pq-native/proof-verify-embedded-test.cpp)
target_link_libraries(test-proof-verify-embedded PRIVATE tos-proof-embedded proof-verify-core)
if(ANDROID)
  target_link_options(test-proof-verify-embedded PRIVATE "-Wl,-z,max-page-size=16384")
endif()

add_test(NAME proof-verify-embedded COMMAND test-proof-verify-embedded
  ${PROJECT_SOURCE_DIR}/test/pq-native/data/proof-verify-real)

if(NOT CMAKE_CROSSCOMPILING)
  find_package(Python3 COMPONENTS Interpreter REQUIRED)
  add_test(NAME self-pay-simulation-inputs COMMAND ${Python3_EXECUTABLE}
    ${PROJECT_SOURCE_DIR}/scripts/check-self-pay-simulation-fixtures.py)
  add_test(NAME self-pay-simulation-input-controls COMMAND ${Python3_EXECUTABLE}
    ${PROJECT_SOURCE_DIR}/scripts/test-self-pay-simulation-fixtures.py)
  add_test(NAME wallet-transaction COMMAND ${Python3_EXECUTABLE}
    ${PROJECT_SOURCE_DIR}/test/pq-native/wallet-transaction-test.py
    $<TARGET_FILE:tos-proof-embedded> ${PROJECT_SOURCE_DIR}/test/pq-native/data/wallet-transactions)
  add_test(NAME proof-acquire-persisted COMMAND ${Python3_EXECUTABLE}
    ${PROJECT_SOURCE_DIR}/test/pq-native/proof-acquire-persisted-test.py
    $<TARGET_FILE:tos-proof-embedded> ${PROJECT_SOURCE_DIR}/test/pq-native/data/proof-verify-real)

  add_test(NAME proof-acquisition-c COMMAND ${Python3_EXECUTABLE}
    ${PROJECT_SOURCE_DIR}/test/pq-native/proof-acquisition-c-test.py
    $<TARGET_FILE:tos-proof-embedded> ${PROJECT_SOURCE_DIR}/test/pq-native/data/proof-verify-real)

  add_library(proof-persisted-fsync-shim SHARED ../../test/pq-native/proof-persisted-fsync-shim.cpp)
  target_link_libraries(proof-persisted-fsync-shim PRIVATE ${CMAKE_DL_LIBS})
  if(APPLE)
    set(PROOF_PERSIST_LOADER DYLD_INSERT_LIBRARIES)
  else()
    set(PROOF_PERSIST_LOADER LD_PRELOAD)
  endif()
  add_test(NAME proof-verify-persisted-sync-fault COMMAND ${CMAKE_COMMAND} -E env
    "${PROOF_PERSIST_LOADER}=$<TARGET_FILE:proof-persisted-fsync-shim>"
    ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/test/pq-native/proof-verify-persisted-test.py
    $<TARGET_FILE:tos-proof-embedded> ${PROJECT_SOURCE_DIR}/test/pq-native/data/proof-verify-real --sync-fault)

  add_test(NAME proof-verify-persisted COMMAND ${Python3_EXECUTABLE}
    ${PROJECT_SOURCE_DIR}/test/pq-native/proof-verify-persisted-test.py
    $<TARGET_FILE:tos-proof-embedded> ${PROJECT_SOURCE_DIR}/test/pq-native/data/proof-verify-real)
endif()

add_executable(test-proof-acquisition ../../test/pq-native/proof-acquisition-test.cpp)
target_link_libraries(test-proof-acquisition PRIVATE proof-verify-core)
add_test(NAME proof-material-acquisition COMMAND test-proof-acquisition ${PROJECT_SOURCE_DIR}/test/pq-native/data/proof-verify-real)

add_executable(test-proof-readonly-query ../../test/pq-native/proof-readonly-query-test.cpp)
target_link_libraries(test-proof-readonly-query PRIVATE proof-verify-engine)
add_test(NAME proof-readonly-query COMMAND test-proof-readonly-query)

add_executable(test-self-pay-simulation-context ../../test/pq-native/self-pay-simulation-context-test.cpp)
target_link_libraries(test-self-pay-simulation-context PRIVATE proof-verify-engine)
add_test(NAME self-pay-simulation-context COMMAND test-self-pay-simulation-context)

add_executable(test-simulation-config ../../test/pq-native/simulation-config-test.cpp)
target_link_libraries(test-simulation-config PRIVATE proof-verify-core)
add_test(NAME simulation-config COMMAND test-simulation-config ${PROJECT_SOURCE_DIR}/test/pq-native/data/proof-verify-real)

add_executable(test-simulation-account ../../test/pq-native/simulation-account-test.cpp)
target_link_libraries(test-simulation-account PRIVATE proof-verify-core)
add_test(NAME simulation-account COMMAND test-simulation-account ${PROJECT_SOURCE_DIR}/test/pq-native/data/proof-verify-real)

add_executable(test-self-pay-simulation ../../test/pq-native/self-pay-simulation-test.cpp)
target_link_libraries(test-self-pay-simulation PRIVATE proof-verify-core)

add_test(NAME self-pay-simulation COMMAND test-self-pay-simulation ${PROJECT_SOURCE_DIR}/test/pq-native/data/self-pay-simulation ${PROJECT_SOURCE_DIR}/test/pq-native/data/proof-verify-real)

add_executable(test-self-pay-simulation-live ../../test/pq-native/self-pay-simulation-live-test.cpp)
target_link_libraries(test-self-pay-simulation-live PRIVATE proof-verify-core)
add_test(NAME self-pay-simulation-live COMMAND test-self-pay-simulation-live ${PROJECT_SOURCE_DIR}/test/pq-native/data/self-pay-simulation-live)
