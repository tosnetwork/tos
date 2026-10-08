# Prefer clang when the caller did not choose a compiler.
#
# GCC has C++20 compatibility issues with this codebase, so a plain configure
# picks clang/clang++ when both are on PATH. Any explicit choice wins and
# disables the detection entirely:
#   - CMAKE_C_COMPILER or CMAKE_CXX_COMPILER on the command line,
#   - CC or CXX in the environment (the standard CMake contract),
#   - a toolchain file (CMAKE_TOOLCHAIN_FILE, as a variable or in the
#     environment), which may set the compilers later,
#   - a Windows host, where clang++ on PATH is the GNU-style driver and the
#     build scripts select MSVC/clang-cl themselves.
# Both compilers are set together or neither is.
#
# Must be included before project().

set(_tos_autodetect_skip FALSE)
foreach(_var CMAKE_C_COMPILER CMAKE_CXX_COMPILER CMAKE_TOOLCHAIN_FILE)
  if(DEFINED ${_var})
    set(_tos_autodetect_skip TRUE)
  endif()
endforeach()
foreach(_env CC CXX CMAKE_TOOLCHAIN_FILE)
  if(DEFINED ENV{${_env}})
    set(_tos_autodetect_skip TRUE)
  endif()
endforeach()
# TOS_AUTODETECT_ASSUME_WIN32 lets the selection test exercise the Windows branch.
if(CMAKE_HOST_WIN32 OR TOS_AUTODETECT_ASSUME_WIN32)
  set(_tos_autodetect_skip TRUE)
endif()

if(NOT _tos_autodetect_skip)
  find_program(_TOS_CLANG_C clang)
  find_program(_TOS_CLANG_CXX clang++)
  if(_TOS_CLANG_C AND _TOS_CLANG_CXX)
    set(CMAKE_C_COMPILER "${_TOS_CLANG_C}" CACHE FILEPATH "C compiler" FORCE)
    set(CMAKE_CXX_COMPILER "${_TOS_CLANG_CXX}" CACHE FILEPATH "C++ compiler" FORCE)
  endif()
endif()
unset(_tos_autodetect_skip)
