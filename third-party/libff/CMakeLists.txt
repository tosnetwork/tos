# libff: Finite field library for alt_bn128 pairing and modexp precompiles.
# Source: erigontech/libff (Apache-2.0).
# Adapted wrapper for the host-chain build system.

set(CURVE "ALT_BN128" CACHE STRING "" FORCE)
option(WITH_PROCPS "" OFF)
option(IS_LIBFF_PARENT "" OFF)

# Find GMP (required by libff for big integer arithmetic)
find_path(GMP_INCLUDE_DIR NAMES gmp.h)
find_library(GMP_LIBRARY gmp)
if(NOT GMP_LIBRARY OR NOT GMP_INCLUDE_DIR)
  message(WARNING "GMP not found — libff disabled (modexp/ecpairing precompiles unavailable)")
  return()
endif()
message(STATUS "GMP: ${GMP_LIBRARY}, ${GMP_INCLUDE_DIR}")

if(GMP_LIBRARY MATCHES "${CMAKE_SHARED_LIBRARY_SUFFIX}")
  set(gmp_library_type SHARED)
else()
  set(gmp_library_type STATIC)
endif()

find_library(GMPXX_LIBRARY gmpxx)

if(NOT TARGET GMP::gmp)
  add_library(GMP::gmp ${gmp_library_type} IMPORTED)
  set_target_properties(GMP::gmp PROPERTIES
    IMPORTED_LOCATION ${GMP_LIBRARY}
    INTERFACE_INCLUDE_DIRECTORIES ${GMP_INCLUDE_DIR}
  )
  # libff uses GMP C++ stream operators
  if(GMPXX_LIBRARY)
    set_property(TARGET GMP::gmp APPEND PROPERTY INTERFACE_LINK_LIBRARIES ${GMPXX_LIBRARY})
  endif()
endif()

# Reduce log verbosity
if(NOT CMAKE_MESSAGE_LOG_LEVEL)
  set(CMAKE_MESSAGE_LOG_LEVEL_EMPTY YES)
  set(CMAKE_MESSAGE_LOG_LEVEL NOTICE)
endif()

# Propagate defines that the root libff CMakeLists.txt would normally set
add_definitions(-DCURVE_ALT_BN128)
add_definitions(-DNO_PROCPS)

add_subdirectory(libff)

if(CMAKE_MESSAGE_LOG_LEVEL_EMPTY)
  unset(CMAKE_MESSAGE_LOG_LEVEL)
endif()
