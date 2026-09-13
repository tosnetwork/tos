cmake_minimum_required(VERSION 3.16)
project(validator_auth_session_birth LANGUAGES CXX)

# Standalone coverage of the birth selector, not a native node build.
get_filename_component(TOS_SOURCE_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)
add_executable(test-p0-session-birth session-birth-test.cpp)
target_include_directories(test-p0-session-birth PRIVATE "${TOS_SOURCE_ROOT}")
set_target_properties(test-p0-session-birth PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
target_compile_options(test-p0-session-birth PRIVATE -Wall -Wextra -Werror -pedantic)
enable_testing()
add_test(NAME p0-session-birth COMMAND test-p0-session-birth)
