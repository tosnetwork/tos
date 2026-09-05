if(NOT DEFINED COLLATOR)
  message(FATAL_ERROR "COLLATOR executable is required")
endif()

function(expect_failure expected)
  execute_process(COMMAND "${COLLATOR}" ${ARGN}
    RESULT_VARIABLE status OUTPUT_VARIABLE output ERROR_VARIABLE errors TIMEOUT 10)
  if(NOT status STREQUAL "2")
    message(FATAL_ERROR "Expected exit 2, got ${status}: ${output}${errors}")
  endif()
  string(FIND "${output}${errors}" "${expected}" found)
  if(found EQUAL -1)
    message(FATAL_ERROR "Missing expected rejection '${expected}': ${output}${errors}")
  endif()
endfunction()

expect_failure("Counter collation requires the unsplit workchain 2"
  --counter-increment 2)
expect_failure("manual collation tool and needs inputs"
  --counter-increment 18446744073709551615 -w 2)
