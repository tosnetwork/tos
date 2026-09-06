foreach(required UNO_CRYPTO_SOURCE UNO_CRYPTO_TARGET_DIR UNO_CRYPTO_CARGO UNO_CRYPTO_BUILD_JOBS)
  if(NOT DEFINED ${required} OR "${${required}}" STREQUAL "")
    message(FATAL_ERROR "Missing ${required}")
  endif()
endforeach()

# Exercise the real build script in a disposable source copy, never edit the checkout.
string(RANDOM LENGTH 20 ALPHABET 0123456789abcdef nonce)
set(fixture "${UNO_CRYPTO_TARGET_DIR}/header-guard-${nonce}")
if(EXISTS "${fixture}")
  message(FATAL_ERROR "Header fixture already exists: ${fixture}")
endif()
file(MAKE_DIRECTORY "${fixture}")
message(STATUS "Header guard fixture (retained on failure): ${fixture}")
file(COPY "${UNO_CRYPTO_SOURCE}/src" "${UNO_CRYPTO_SOURCE}/include"
          "${UNO_CRYPTO_SOURCE}/fixtures"
     DESTINATION "${fixture}")
foreach(name Cargo.toml Cargo.lock build.rs cbindgen.toml rust-toolchain.toml)
  file(COPY "${UNO_CRYPTO_SOURCE}/${name}" DESTINATION "${fixture}")
endforeach()
set(header "${fixture}/include/uno_crypto.h")
# Give each source fixture a distinct package identity while reusing dependency
# artifacts. A shared local package identity can reuse a previous script binary.
foreach(name Cargo.toml Cargo.lock)
  file(READ "${fixture}/${name}" contents)
  string(REPLACE "name = \"tos-uno-crypto-prototype\""
                 "name = \"tos-uno-header-fixture-${nonce}\"" contents "${contents}")
  file(WRITE "${fixture}/${name}" "${contents}")
endforeach()
file(READ "${header}" canonical)

function(build_case label output success)
  set(environment --unset=UNO_CRYPTO_HEADER_OUT "CARGO_NET_OFFLINE=true"
                  "CARGO_TARGET_DIR=${UNO_CRYPTO_TARGET_DIR}")
  if(NOT "${output}" STREQUAL "")
    list(APPEND environment "UNO_CRYPTO_HEADER_OUT=${output}")
  endif()
  execute_process(COMMAND "${CMAKE_COMMAND}" -E env ${environment}
                  "${UNO_CRYPTO_CARGO}" build --locked --offline --release -j${UNO_CRYPTO_BUILD_JOBS}
    WORKING_DIRECTORY "${fixture}" RESULT_VARIABLE result
    OUTPUT_VARIABLE stdout ERROR_VARIABLE stderr TIMEOUT 180)
  file(WRITE "${fixture}/${label}.log" "${stdout}\n${stderr}")
  if(success AND NOT "${result}" STREQUAL "0")
    message(FATAL_ERROR "${label}: expected success; see ${fixture}/${label}.log")
  elseif(NOT success AND NOT "${result}" STREQUAL "101")
    message(FATAL_ERROR "${label}: expected Cargo failure, got ${result}; see ${fixture}/${label}.log")
  endif()
endfunction()

build_case(baseline "" TRUE)
file(APPEND "${header}" "\n/* deliberate header drift */\n")
file(READ "${header}" drifted)
build_case(drift_same_path "${header}" FALSE)
file(READ "${header}" after)
if(NOT "${after}" STREQUAL "${drifted}")
  message(FATAL_ERROR "Build overwrote the drifted committed header: ${fixture}")
endif()
build_case(drift_new_path "${fixture}/unexpected.h" FALSE)
if(EXISTS "${fixture}/unexpected.h")
  message(FATAL_ERROR "Build exported an unverified header: ${fixture}")
endif()

file(WRITE "${header}" "${canonical}")
build_case(verified_export "${fixture}/exported.h" TRUE)
file(READ "${fixture}/exported.h" exported)
if(NOT "${exported}" STREQUAL "${canonical}")
  message(FATAL_ERROR "Verified export differs: ${fixture}")
endif()
# Change the environment between calls so Cargo reruns the export path.
build_case(restored "" TRUE)
build_case(existing_header "${header}" FALSE)
file(CREATE_LINK "${header}" "${fixture}/alias.h" SYMBOLIC RESULT linked)
if(NOT "${linked}" STREQUAL "0")
  message(FATAL_ERROR "Cannot create alias control: ${linked}")
endif()
build_case(existing_alias "${fixture}/alias.h" FALSE)
file(CREATE_LINK "${header}" "${fixture}/hardlink.h" RESULT linked)
if(NOT "${linked}" STREQUAL "0")
  message(FATAL_ERROR "Cannot create hardlink control: ${linked}")
endif()
build_case(existing_hardlink "${fixture}/hardlink.h" FALSE)
file(READ "${header}" after)
if(NOT "${after}" STREQUAL "${canonical}")
  message(FATAL_ERROR "Existing header changed: ${fixture}")
endif()
build_case(final "" TRUE)
execute_process(COMMAND "${CMAKE_COMMAND}" -E env "CARGO_NET_OFFLINE=true"
    "CARGO_TARGET_DIR=${UNO_CRYPTO_TARGET_DIR}" "${UNO_CRYPTO_CARGO}"
    clean --release --package "tos-uno-header-fixture-${nonce}"
    WORKING_DIRECTORY "${fixture}" RESULT_VARIABLE cleaned
    OUTPUT_VARIABLE clean_out ERROR_VARIABLE clean_err TIMEOUT 60)
if(NOT "${cleaned}" STREQUAL "0")
  message(FATAL_ERROR "Cannot clean header fixture artifacts: ${clean_out}\n${clean_err}")
endif()
file(REMOVE_RECURSE "${fixture}")
if(EXISTS "${fixture}")
  message(FATAL_ERROR "Cannot clean successful header fixture: ${fixture}")
endif()
message(STATUS "Header drift and non-overwrite controls passed")
