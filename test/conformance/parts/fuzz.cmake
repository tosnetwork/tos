# Differential fuzzing (docs/fuzz.md): an in-process driver that loads two libraries with the conformance C
# interface and compares their effects on generated contexts, a libFuzzer entry when the compiler has one,
# self-contained copies of the reference library for its self-checks (one of them with a deliberately
# changed gas cost), and the switch for the test-only VM step trace.

# The VM step trace hook (crypto/vm/step-trace.h) is compiled only when this is ON. It is for test builds:
# a build with it is not a production build.
option(TOS_VM_STEP_TRACE "Test builds only: compile the per-step VM trace hook used by conformance diagnosis." OFF)
if (TOS_VM_STEP_TRACE)
  message(WARNING "TOS_VM_STEP_TRACE is ON: this build carries the VM step trace hook and is for tests only")
  target_compile_definitions(tos_crypto_core PUBLIC TOS_VM_STEP_TRACE)
endif()

set(CONFORMANCE_FUZZ_DIR ${CONFORMANCE_DIR}/fuzz)

add_library(conformance-fuzz-core STATIC
  ${CONFORMANCE_FUZZ_DIR}/json.cpp
  ${CONFORMANCE_FUZZ_DIR}/generator.cpp
  ${CONFORMANCE_FUZZ_DIR}/differ.cpp)
target_include_directories(conformance-fuzz-core PUBLIC ${CONFORMANCE_FUZZ_DIR})
target_link_libraries(conformance-fuzz-core PUBLIC tos_crypto tdutils ${CMAKE_DL_LIBS})

add_executable(conformance-fuzz ${CONFORMANCE_FUZZ_DIR}/driver-main.cpp)
target_link_libraries(conformance-fuzz PRIVATE conformance-fuzz-core)

include(CheckCXXSourceCompiles)
set(CMAKE_REQUIRED_FLAGS "-fsanitize=fuzzer")
set(CMAKE_REQUIRED_LINK_OPTIONS "-fsanitize=fuzzer")
check_cxx_source_compiles([=[
#include <cstddef>
#include <cstdint>
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *, std::size_t) { return 0; }
]=] CONFORMANCE_FUZZ_HAVE_LIBFUZZER)
unset(CMAKE_REQUIRED_FLAGS)
unset(CMAKE_REQUIRED_LINK_OPTIONS)
if (CONFORMANCE_FUZZ_HAVE_LIBFUZZER)
  # The generator is compiled with coverage too, so the fuzzer is guided by which grammar paths an input takes.
  # The libraries under test are not instrumented.
  add_executable(conformance-fuzz-libfuzzer ${CONFORMANCE_FUZZ_DIR}/libfuzzer-entry.cpp ${CONFORMANCE_FUZZ_DIR}/json.cpp
    ${CONFORMANCE_FUZZ_DIR}/generator.cpp ${CONFORMANCE_FUZZ_DIR}/differ.cpp)
  target_include_directories(conformance-fuzz-libfuzzer PRIVATE ${CONFORMANCE_FUZZ_DIR})
  target_compile_options(conformance-fuzz-libfuzzer PRIVATE -fsanitize=fuzzer)
  target_link_options(conformance-fuzz-libfuzzer PRIVATE -fsanitize=fuzzer)
  target_link_libraries(conformance-fuzz-libfuzzer PRIVATE tos_crypto tdutils ${CMAKE_DL_LIBS})
endif()

# Self-contained copies of the reference library: every dependency linked in statically, every symbol but the
# conformance interface local and bound inside the copy, so a copy and the reference can share one process.
set(CONFORMANCE_FUZZ_EXPORTS ${CMAKE_CURRENT_BINARY_DIR}/fuzz-exports.map)
file(WRITE ${CONFORMANCE_FUZZ_EXPORTS} "{ global: conformance_*; local: *; };\n")

function(conformance_fuzz_library name)
  add_library(${name} SHARED ${CONFORMANCE_REF_SOURCES} ${CMAKE_SOURCE_DIR}/emulator/emulator-extern.cpp ${ARGN})
  target_include_directories(${name} PRIVATE ${CMAKE_SOURCE_DIR}/emulator ${CMAKE_BINARY_DIR}/emulator
    ${CONFORMANCE_REF_DIR})
  # The same libraries the reference links for its harnesses, evaluated at generation time so every part
  # counts, but static: the shared emulator is replaced by emulator_static and emulator-extern.cpp above.
  target_link_libraries(${name} PRIVATE emulator_static git
    "$<FILTER:$<TARGET_PROPERTY:conformance-ref,LINK_LIBRARIES>,EXCLUDE,^(emulator|git)$>")
  target_link_options(${name} PRIVATE -Wl,-Bsymbolic -Wl,--version-script=${CONFORMANCE_FUZZ_EXPORTS})
  add_dependencies(${name} emulator)  # emulator_export.h
endfunction()

conformance_fuzz_library(conformance-ref-fuzz-twin)

# The mutant: the twin with crypto/vm/vm.cpp replaced by a copy in which the implicit JMPREF costs
# CONFORMANCE_FUZZ_MUTANT_GAS_DELTA more gas. It exists only to show that the differential checks find a
# one-constant change; nothing outside these checks links it.
set(CONFORMANCE_FUZZ_VM_SOURCE ${CMAKE_SOURCE_DIR}/crypto/vm/vm.cpp)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${CONFORMANCE_FUZZ_VM_SOURCE})
file(READ ${CONFORMANCE_FUZZ_VM_SOURCE} conformance_fuzz_vm_text)
set(conformance_fuzz_needle "consume_gas_chk(implicit_jmpref_gas_price);")
string(FIND "${conformance_fuzz_vm_text}" "${conformance_fuzz_needle}" conformance_fuzz_at)
if (conformance_fuzz_at EQUAL -1)
  message(FATAL_ERROR "fuzz mutant: '${conformance_fuzz_needle}' not found in crypto/vm/vm.cpp")
endif()
string(REPLACE "${conformance_fuzz_needle}"
  "consume_gas_chk(implicit_jmpref_gas_price + CONFORMANCE_FUZZ_MUTANT_GAS_DELTA);"
  conformance_fuzz_vm_text "${conformance_fuzz_vm_text}")
set(CONFORMANCE_FUZZ_MUTANT_SOURCE ${CMAKE_CURRENT_BINARY_DIR}/fuzz-mutant/vm-mutant.cpp)
file(WRITE ${CONFORMANCE_FUZZ_MUTANT_SOURCE}.new "${conformance_fuzz_vm_text}")
execute_process(COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CONFORMANCE_FUZZ_MUTANT_SOURCE}.new
  ${CONFORMANCE_FUZZ_MUTANT_SOURCE})
conformance_fuzz_library(conformance-ref-fuzz-mutant ${CONFORMANCE_FUZZ_MUTANT_SOURCE})
set_source_files_properties(${CONFORMANCE_FUZZ_MUTANT_SOURCE} PROPERTIES
  COMPILE_DEFINITIONS CONFORMANCE_FUZZ_MUTANT_GAS_DELTA=1)
target_include_directories(conformance-ref-fuzz-mutant PRIVATE ${CMAKE_SOURCE_DIR}/crypto/vm)
add_executable(conformance-fuzz-mutant-cli ${CONFORMANCE_REF_DIR}/conformance-ref-cli.cpp)
target_link_libraries(conformance-fuzz-mutant-cli PRIVATE conformance-ref-fuzz-mutant)
target_include_directories(conformance-fuzz-mutant-cli PRIVATE ${CONFORMANCE_REF_DIR})

# ---------------------------------------------------------------------------------------------
# Checks. Each campaign is deterministic (fixed seed); the mutant ones must find mismatches.

set(CONFORMANCE_FUZZ_OUT ${CMAKE_CURRENT_BINARY_DIR}/fuzz-out)
set(CONFORMANCE_FUZZ_SEEDS ${CONFORMANCE_DIR}/vectors)
set(CONFORMANCE_FUZZ_CASES 3000)

add_test(NAME conformance-fuzz-self
  COMMAND conformance-fuzz --harness vm --reference $<TARGET_FILE:conformance-ref>
    --target $<TARGET_FILE:conformance-ref> --seeds ${CONFORMANCE_FUZZ_SEEDS} --cases ${CONFORMANCE_FUZZ_CASES}
    --seed 11)
add_test(NAME conformance-fuzz-twin
  COMMAND conformance-fuzz --harness vm --reference $<TARGET_FILE:conformance-ref>
    --target $<TARGET_FILE:conformance-ref-fuzz-twin> --seeds ${CONFORMANCE_FUZZ_SEEDS}
    --cases ${CONFORMANCE_FUZZ_CASES} --seed 12)
add_test(NAME conformance-fuzz-clean COMMAND ${CMAKE_COMMAND} -E rm -rf ${CONFORMANCE_FUZZ_OUT})
set_tests_properties(conformance-fuzz-clean PROPERTIES FIXTURES_SETUP conformance-fuzz-clean)
add_test(NAME conformance-fuzz-mutant
  COMMAND conformance-fuzz --harness vm --reference $<TARGET_FILE:conformance-ref>
    --target $<TARGET_FILE:conformance-ref-fuzz-mutant> --seeds ${CONFORMANCE_FUZZ_SEEDS}
    --cases ${CONFORMANCE_FUZZ_CASES} --seed 13 --out ${CONFORMANCE_FUZZ_OUT}/in-process --expect-mismatch)
set_tests_properties(conformance-fuzz-mutant PROPERTIES FIXTURES_SETUP conformance-fuzz-mutant-files
  FIXTURES_REQUIRED conformance-fuzz-clean)

# The process-level driver over command-line targets, on the same cases: itself must agree, the mutant must
# not, and its mismatch files must be exactly the in-process driver's.
set(CONFORMANCE_FUZZ_PROCESS ${Python3_EXECUTABLE} -B ${CONFORMANCE_DIR}/runner/fuzz_process.py run
  --generator $<TARGET_FILE:conformance-fuzz> --harness vm --seeds ${CONFORMANCE_FUZZ_SEEDS}
  --cases ${CONFORMANCE_FUZZ_CASES})
add_test(NAME conformance-fuzz-process-self
  COMMAND ${CONFORMANCE_FUZZ_PROCESS} --seed 11 --reference $<TARGET_FILE:conformance-ref-cli>
    --target $<TARGET_FILE:conformance-ref-cli>)
add_test(NAME conformance-fuzz-process-mutant
  COMMAND ${CONFORMANCE_FUZZ_PROCESS} --seed 13 --reference $<TARGET_FILE:conformance-ref-cli>
    --target $<TARGET_FILE:conformance-fuzz-mutant-cli> --out ${CONFORMANCE_FUZZ_OUT}/process --expect-mismatch
    --same-mismatches-as ${CONFORMANCE_FUZZ_OUT}/in-process)
set_tests_properties(conformance-fuzz-process-mutant PROPERTIES
  FIXTURES_REQUIRED "conformance-fuzz-clean;conformance-fuzz-mutant-files")

# txn: mutations of the REL-02 chain contexts.
if (TARGET test-epoch-replay)
  set(CONFORMANCE_FUZZ_TXN_SEEDS ${CONFORMANCE_FUZZ_OUT}/rel02-seeds.jsonl)
  add_test(NAME conformance-fuzz-txn-seeds
    COMMAND ${Python3_EXECUTABLE} -B ${CONFORMANCE_DIR}/runner/fuzz_process.py rel02-seeds
      $<TARGET_FILE:test-epoch-replay> ${CMAKE_SOURCE_DIR}/test/rel02/corpus ${CONFORMANCE_FUZZ_TXN_SEEDS})
  set_tests_properties(conformance-fuzz-txn-seeds PROPERTIES FIXTURES_SETUP conformance-fuzz-txn-seeds
    FIXTURES_REQUIRED conformance-fuzz-clean)
  add_test(NAME conformance-fuzz-txn-twin
    COMMAND conformance-fuzz --harness txn --reference $<TARGET_FILE:conformance-ref>
      --target $<TARGET_FILE:conformance-ref-fuzz-twin> --seeds ${CONFORMANCE_FUZZ_TXN_SEEDS} --cases 300 --seed 21)
  add_test(NAME conformance-fuzz-txn-mutant
    COMMAND conformance-fuzz --harness txn --reference $<TARGET_FILE:conformance-ref>
      --target $<TARGET_FILE:conformance-ref-fuzz-mutant> --seeds ${CONFORMANCE_FUZZ_TXN_SEEDS} --cases 300
      --seed 22 --out ${CONFORMANCE_FUZZ_OUT}/txn --expect-mismatch)
  set_tests_properties(conformance-fuzz-txn-twin conformance-fuzz-txn-mutant PROPERTIES
    FIXTURES_REQUIRED conformance-fuzz-txn-seeds)
endif()

if (CONFORMANCE_FUZZ_HAVE_LIBFUZZER)
  add_test(NAME conformance-fuzz-libfuzzer
    COMMAND ${CMAKE_COMMAND} -E env CONFORMANCE_FUZZ_REFERENCE=$<TARGET_FILE:conformance-ref>
      CONFORMANCE_FUZZ_TARGET=$<TARGET_FILE:conformance-ref-fuzz-twin> CONFORMANCE_FUZZ_SEEDS=${CONFORMANCE_FUZZ_SEEDS}
      CONFORMANCE_FUZZ_ABORT=1
      $<TARGET_FILE:conformance-fuzz-libfuzzer> -runs=2000 -seed=1)
endif()

# The step trace: with the hook a mutant mismatch is located at its first diverging step; without it a trace
# request is refused.
if (TOS_VM_STEP_TRACE)
  set(CONFORMANCE_FUZZ_TRACE_MODE on)
else()
  set(CONFORMANCE_FUZZ_TRACE_MODE off)
endif()
add_test(NAME conformance-fuzz-trace
  COMMAND ${Python3_EXECUTABLE} -B ${CONFORMANCE_DIR}/runner/debug_mismatch.py --expect-trace
    ${CONFORMANCE_FUZZ_TRACE_MODE} --reference $<TARGET_FILE:conformance-ref-cli>
    --target $<TARGET_FILE:conformance-fuzz-mutant-cli> --first-of ${CONFORMANCE_FUZZ_OUT}/in-process)
set_tests_properties(conformance-fuzz-trace PROPERTIES FIXTURES_REQUIRED conformance-fuzz-mutant-files)

set_tests_properties(conformance-fuzz-clean conformance-fuzz-self conformance-fuzz-twin conformance-fuzz-mutant
  conformance-fuzz-process-self conformance-fuzz-process-mutant conformance-fuzz-trace
  PROPERTIES LABELS "conformance" TIMEOUT 900)
if (TARGET test-epoch-replay)
  set_tests_properties(conformance-fuzz-txn-seeds conformance-fuzz-txn-twin conformance-fuzz-txn-mutant
    PROPERTIES LABELS "conformance" TIMEOUT 1800)
endif()
if (CONFORMANCE_FUZZ_HAVE_LIBFUZZER)
  set_tests_properties(conformance-fuzz-libfuzzer PROPERTIES LABELS "conformance" TIMEOUT 900)
endif()
