# TOS Avata interpreter CMake bridge.
#
# The Avata fork is still built by its canonical makefile because that makefile
# owns rt.jar/api.jar generation, type metadata generation, SoftFloat sources,
# and platform flags. This CMake file exposes the resulting static interpreter
# archive as a normal target for the TOS build graph.

find_program(AVATA_MAKE_EXECUTABLE NAMES gmake make REQUIRED)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  set(AVATA_MAKE_PLATFORM linux)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
  set(AVATA_MAKE_PLATFORM macosx)
elseif(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
  set(AVATA_MAKE_PLATFORM freebsd)
elseif(WIN32)
  set(AVATA_MAKE_PLATFORM windows)
else()
  message(FATAL_ERROR "Unsupported Avata CMake bridge platform: ${CMAKE_SYSTEM_NAME}")
endif()

string(TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" AVATA_CMAKE_PROCESSOR)
if(AVATA_CMAKE_PROCESSOR MATCHES "^(x86_64|amd64)$")
  set(AVATA_MAKE_ARCH x86_64)
elseif(AVATA_CMAKE_PROCESSOR MATCHES "^(i386|i686|x86)$")
  set(AVATA_MAKE_ARCH i386)
elseif(AVATA_CMAKE_PROCESSOR MATCHES "^(aarch64|arm64)$")
  set(AVATA_MAKE_ARCH arm64)
elseif(AVATA_CMAKE_PROCESSOR MATCHES "^arm")
  set(AVATA_MAKE_ARCH arm)
else()
  message(FATAL_ERROR "Unsupported Avata CMake bridge architecture: ${CMAKE_SYSTEM_PROCESSOR}")
endif()

set(AVATA_MAKE_BUILD_DIR
    "${CMAKE_CURRENT_SOURCE_DIR}/build/${AVATA_MAKE_PLATFORM}-${AVATA_MAKE_ARCH}")
set(AVATA_STATIC_LIBRARY
    "${AVATA_MAKE_BUILD_DIR}/libavata.a")

add_custom_target(avata_interpreter_build
  COMMAND "${AVATA_MAKE_EXECUTABLE}"
          -C "${CMAKE_CURRENT_SOURCE_DIR}"
          platform=${AVATA_MAKE_PLATFORM}
          arch=${AVATA_MAKE_ARCH}
          process=interpret
          mode=fast
          "${AVATA_STATIC_LIBRARY}"
  BYPRODUCTS "${AVATA_STATIC_LIBRARY}"
             "${AVATA_MAKE_BUILD_DIR}/rt.jar"
             "${AVATA_MAKE_BUILD_DIR}/api.jar"
  USES_TERMINAL
  VERBATIM
  COMMENT "Building Avata interpreter static library")

add_library(avata_interpreter STATIC IMPORTED GLOBAL)
set_target_properties(avata_interpreter PROPERTIES
  IMPORTED_LOCATION "${AVATA_STATIC_LIBRARY}"
  INTERFACE_INCLUDE_DIRECTORIES
    "${CMAKE_CURRENT_SOURCE_DIR}/include;${CMAKE_CURRENT_SOURCE_DIR}/src;${CMAKE_CURRENT_SOURCE_DIR}/rt"
  INTERFACE_COMPILE_DEFINITIONS
    "TOS_AVATA_DEFAULT_RT_JAR=\"${AVATA_MAKE_BUILD_DIR}/rt.jar\""
  INTERFACE_LINK_LIBRARIES
    "${ZLIB_LIBRARIES};${CMAKE_DL_LIBS}")
add_dependencies(avata_interpreter avata_interpreter_build)
