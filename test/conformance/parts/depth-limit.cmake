# The text of a result value is depth-bounded: 512 nested tuples are reported, 513 are refused, never a crash.
add_test(NAME conformance-depth-limit
  COMMAND ${Python3_EXECUTABLE} -B ${CONFORMANCE_DIR}/migrate/depth_limit.py $<TARGET_FILE:conformance-ref-cli>)
set_tests_properties(conformance-depth-limit PROPERTIES LABELS "conformance" TIMEOUT 300)
