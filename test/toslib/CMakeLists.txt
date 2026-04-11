set(TOSLIB_TESTS
    test-ffi-awaitable
)

# FIXME: Enable this on MacOS once we figure out why it fails in CI because of too slow wake ups.
if(NOT APPLE)
    list(APPEND TOSLIB_TESTS test-ffi-event-loop)
endif()

foreach(TEST_NAME IN LISTS TOSLIB_TESTS)
    add_executable(${TEST_NAME} ${TEST_NAME}.cpp)

    target_link_libraries(${TEST_NAME} PRIVATE td-test-main toslibjson_objects toslibjson_private_interface)

    tos_test(${TEST_NAME})
endforeach()
