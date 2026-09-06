function(uno_require_cargo cargo source)
  execute_process(COMMAND "${CMAKE_COMMAND}" -E env "CARGO_NET_OFFLINE=true" "${cargo}" --version
    WORKING_DIRECTORY "${source}" RESULT_VARIABLE status
    OUTPUT_VARIABLE version ERROR_VARIABLE diagnostic OUTPUT_STRIP_TRAILING_WHITESPACE)
  if (NOT "${status}" STREQUAL "0" OR NOT version MATCHES "^cargo 1\\.97\\.1 ")
    message(FATAL_ERROR "UNO requires cargo 1.97.1 from the pinned toolchain; got '${version}' (${status}): ${diagnostic}")
  endif()
endfunction()
