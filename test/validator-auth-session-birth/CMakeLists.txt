cmake_minimum_required(VERSION 3.16)
project(validator_auth_session_birth LANGUAGES CXX)

# Standalone coverage of the birth selector, not a native node build.
get_filename_component(TOS_SOURCE_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)
add_executable(test-p0-session-birth session-birth-test.cpp)
target_include_directories(test-p0-session-birth PRIVATE "${TOS_SOURCE_ROOT}")
set_target_properties(test-p0-session-birth PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
target_compile_options(test-p0-session-birth PRIVATE -Wall -Wextra -Werror -pedantic)

# The admission target consumes the selector through a bounded authenticated
# reader contract and owns the derived committee for the native lifetime. It is
# standalone until the native manager adapter is installed.
add_executable(test-p0-session-admission session-admission-test.cpp)
target_include_directories(test-p0-session-admission PRIVATE "${TOS_SOURCE_ROOT}")
set_target_properties(test-p0-session-admission PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
target_compile_options(test-p0-session-admission PRIVATE -Wall -Wextra -Werror -pedantic)

find_package(Python3 COMPONENTS Interpreter REQUIRED)
enable_testing()
add_test(NAME p0-session-birth COMMAND test-p0-session-birth)
add_test(NAME p0-session-admission COMMAND test-p0-session-admission)
add_test(NAME p0-session-admission-mutations
         COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/admission_mutations.py
                 --out ${CMAKE_CURRENT_BINARY_DIR}/admission-mutations)
