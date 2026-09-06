foreach(required UNO_CRYPTO_CARGO UNO_CRYPTO_SOURCE UNO_CRYPTO_TARGET_DIR UNO_CRYPTO_BUILD_JOBS UNO_CRYPTO_FIXTURE_ROOT UNO_CRYPTO_ABI_EXE)
  if (NOT DEFINED ${required} OR "${${required}}" STREQUAL "")
    message(FATAL_ERROR "Missing ${required}")
  endif()
endforeach()
string(RANDOM LENGTH 20 ALPHABET 0123456789abcdef nonce)
set(fixture_dir "${UNO_CRYPTO_FIXTURE_ROOT}/${nonce}")
if (EXISTS "${fixture_dir}")
  message(FATAL_ERROR "Fixture directory already exists")
endif()
file(MAKE_DIRECTORY "${fixture_dir}")
execute_process(
  COMMAND "${CMAKE_COMMAND}" -E env "CARGO_NET_OFFLINE=true" "CARGO_TARGET_DIR=${UNO_CRYPTO_TARGET_DIR}"
    "UNO_ABI_FIXTURE_DIR=${fixture_dir}" "${UNO_CRYPTO_CARGO}"
    test --locked --offline --release -j${UNO_CRYPTO_BUILD_JOBS} --lib real_bundle_requires_proof_and_signatures
  WORKING_DIRECTORY "${UNO_CRYPTO_SOURCE}"
  RESULT_VARIABLE generated OUTPUT_VARIABLE generated_out ERROR_VARIABLE generated_err)
if (NOT "${generated}" STREQUAL "0")
  message(FATAL_ERROR "Fixture generation failed (${generated}):\n${generated_out}\n${generated_err}")
endif()
foreach(name output-only.bin spend.bin)
  if (NOT EXISTS "${fixture_dir}/${name}")
    message(FATAL_ERROR "Fixture generator succeeded without ${name}")
  endif()
endforeach()
execute_process(COMMAND "${UNO_CRYPTO_ABI_EXE}" "${fixture_dir}/output-only.bin" "${fixture_dir}/spend.bin"
  RESULT_VARIABLE verified OUTPUT_VARIABLE verified_out ERROR_VARIABLE verified_err)
if (NOT "${verified}" STREQUAL "0")
  message(FATAL_ERROR "Real C++ ABI verification failed (${verified}):\n${verified_out}\n${verified_err}")
endif()
message(STATUS "${verified_out}Public fixtures retained at ${fixture_dir}")
