add_executable(test-p0-implementation driver.cpp)
target_link_libraries(test-p0-implementation PRIVATE tos_validator_auth)
set_target_properties(test-p0-implementation PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)

add_executable(test-p0-transfer transfer-test.cpp)
target_link_libraries(test-p0-transfer PRIVATE tos_validator_auth)
set_target_properties(test-p0-transfer PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)

add_executable(test-p0-transport transport-driver.cpp)
target_link_libraries(test-p0-transport PRIVATE tos_validator_auth)
set_target_properties(test-p0-transport PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)

add_executable(test-p0-cells cells-test.cpp)
target_link_libraries(test-p0-cells PRIVATE tos_validator_auth)
set_target_properties(test-p0-cells PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
# The mutation harness edits this build-tree copy, never production sources.
configure_file("${PROJECT_SOURCE_DIR}/validator/auth/cells.cpp" "${CMAKE_CURRENT_BINARY_DIR}/mutated-cells.cpp" COPYONLY)
add_executable(test-p0-cells-mutant EXCLUDE_FROM_ALL cells-test.cpp "${CMAKE_CURRENT_BINARY_DIR}/mutated-cells.cpp")
target_include_directories(test-p0-cells-mutant PRIVATE "${PROJECT_SOURCE_DIR}/validator/auth")
target_link_libraries(test-p0-cells-mutant PRIVATE tos_validator_auth)
set_target_properties(test-p0-cells-mutant PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
