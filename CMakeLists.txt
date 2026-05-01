cmake_minimum_required(VERSION 3.16 FATAL_ERROR)

# Prefer clang — GCC has C++20 compatibility issues with this codebase.
if(NOT DEFINED CMAKE_C_COMPILER AND NOT DEFINED CMAKE_CXX_COMPILER)
  find_program(_CLANG_C   clang)
  find_program(_CLANG_CXX clang++)
  if(_CLANG_C AND _CLANG_CXX)
    set(CMAKE_C_COMPILER   "${_CLANG_C}"   CACHE FILEPATH "C compiler"   FORCE)
    set(CMAKE_CXX_COMPILER "${_CLANG_CXX}" CACHE FILEPATH "C++ compiler" FORCE)
  endif()
endif()

project(TOS VERSION 0.5 LANGUAGES C CXX)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Define the two required variables before including the source code for watching a git repository.
# Only set up git tracking if not already done at a higher level
if(NOT TARGET git)
  set(PRE_CONFIGURE_FILE "git.cc.in")
  set(POST_CONFIGURE_FILE "${CMAKE_CURRENT_BINARY_DIR}/git.cc")
  include(git_watcher.cmake)

  # Create a library out of the compiled post-configure file.
  add_library(git STATIC ${POST_CONFIGURE_FILE})
  target_include_directories(git PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
  add_dependencies(git check_git)
endif()

# Prevent in-source build
get_filename_component(TOS_REAL_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}" REALPATH)
get_filename_component(TOS_REAL_BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}" REALPATH)

if (TOS_REAL_BINARY_DIR STREQUAL TOS_REAL_SOURCE_DIR)
  message("  Out-of-source build should be used to build TOS.")
  message("  You need to remove the files already created by CMake and")
  message("  rerun CMake from a new directory:")
  message("  rm -rf CMakeFiles CMakeCache.txt")
  message("  mkdir build")
  message("  cd build")
  message("  cmake ..")
  message(FATAL_ERROR "In-source build failed.")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)
set(CMAKE_CXX_EXTENSIONS FALSE)

set(CMAKE_COLOR_DIAGNOSTICS TRUE)

if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  set(GCC 1)
elseif (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  set(CLANG 1)
elseif (CMAKE_CXX_COMPILER_ID STREQUAL "Intel")
  set(INTEL 1)
elseif (NOT MSVC)
  message(FATAL_ERROR "Compiler isn't supported")
endif()

if (MINGW)
  if (NOT CMAKE_AR OR NOT EXISTS "${CMAKE_AR}")
    find_program(TOS_LLVM_AR NAMES llvm-ar)
    if (TOS_LLVM_AR)
      set(CMAKE_AR "${TOS_LLVM_AR}" CACHE FILEPATH "Archiver" FORCE)
    endif()
  endif()
  if (NOT CMAKE_RANLIB OR NOT EXISTS "${CMAKE_RANLIB}")
    find_program(TOS_LLVM_RANLIB NAMES llvm-ranlib ranlib)
    if (TOS_LLVM_RANLIB)
      set(CMAKE_RANLIB "${TOS_LLVM_RANLIB}" CACHE FILEPATH "Ranlib" FORCE)
    endif()
  endif()
  # OpenSSL static libs need Windows socket/crypto system libs on MinGW.
  link_libraries(ws2_32 crypt32)
endif()

#BEGIN internal
option(BUILD_SHARED_LIBS "Use \"ON\" to build shared libraries instead of static where it's not specified (not recommended)" OFF)
option(USE_EMSCRIPTEN "Use \"ON\" for config building wasm." OFF)
option(TOS_ONLY_TOSLIB "Use \"ON\" to build only toslib." OFF)
if (USE_EMSCRIPTEN)
  set(TOS_ONLY_TOSLIB true)
endif()
if (TOS_ONLY_TOSLIB)
  set(NOT_TOS_ONLY_TOSLIB false)
else()
  set(NOT_TOS_ONLY_TOSLIB true)
endif()
option(TOS_USE_ROCKSDB "Use \"ON\" to enable RocksDb." ${NOT_TOS_ONLY_TOSLIB})
option(TOS_USE_ABSEIL "Use \"ON\" to enable Abseil." ${NOT_TOS_ONLY_TOSLIB})
option(TOS_USE_JEMALLOC "Use \"ON\" to enable JeMalloc." OFF)
#END internal

option(TOSLIB_ENABLE_JNI "Use \"ON\" to enable JNI-compatible TosLib API.")
option(TOS_USE_ASAN "Use \"ON\" to enable AddressSanitizer." OFF)
option(TOS_USE_TSAN "Use \"ON\" to enable ThreadSanitizer." OFF)
option(TOS_USE_UBSAN "Use \"ON\" to enable UndefinedBehaviorSanitizer." OFF)
option(TOS_USE_COVERAGE "Use \"ON\" to enable code coverage with gcov." OFF)
option(TOS_BUILD_LIBFUZZER "Build optional libFuzzer harnesses (requires clang)" OFF)
set(TOS_ARCH "native" CACHE STRING "Architecture, will be passed to -march=")

option(TOS_PRINT_BACKTRACE_ON_CRASH "Attempt to print a backtrace when a fatal signal is caught" ON)
option(TOS_INSERT_GDB_HOOKS "Insert GDB hooks" OFF)

option(TOS_USE_LLD "Use LLD for linking" OFF)

if (TOS_USE_LLD)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fuse-ld=lld")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -fuse-ld=lld")
    set(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS} -fuse-ld=lld")
endif()

#BEGIN M1 support
EXECUTE_PROCESS( COMMAND uname -m COMMAND tr -d '\n' OUTPUT_VARIABLE ARCHITECTURE )

if ((ARCHITECTURE MATCHES "arm64") AND (CMAKE_SYSTEM_NAME STREQUAL "Darwin") AND
    (CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 13.0)) # only clang 13+ supports cpu=apple-m1
    set(TOS_ARCH "apple-m1")
endif()
#END M1 support

option(TOS_WERROR_BUILD "Use -Werror" OFF)

# If we want to check -Werror build in CI, we want to use it for third party projects as well but we
# don't want to force our warning options on them.
if (TOS_WERROR_BUILD)
  add_compile_options(-Werror)
endif()

# Ensure custom build modules (including OpenSSL/Sodium) are available early for QUIC/crypto checks.
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/CMake" ${CMAKE_MODULE_PATH})
include(BuildOpenSSL)
include(BuildSodium)
include(BuildLZ4)

# -----------------------------------------------------------------------------
# corrosion-rs — CMake ↔ Cargo integration for the Uno wc=2 Rust FFI crate
# (`uno/plonky3-ffi/`, produces `libuno_plonky3_ffi.a`). Vendored at
# `third-party/corrosion/` at release tag v0.5.2 — see
# `third-party/corrosion/README.uno.md` for upstream pin + refresh policy.
#
# Added here (before `add_subdirectory(uno)` below) so the `Corrosion::*`
# targets and `corrosion_import_crate(...)` function are visible when
# `uno/CMakeLists.txt` calls them. Guarded by file existence so a stripped
# checkout (no Rust toolchain available) still configures; in that case
# `uno/CMakeLists.txt`'s `find_package(Corrosion QUIET)` returns not-found
# and the Plonky3 bridge falls back to the weak-symbol stubs in
# `uno/core/parallel-verify.cpp`.
# -----------------------------------------------------------------------------
if (NOT TOS_ONLY_TOSLIB AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/third-party/corrosion/CMakeLists.txt")
  message("Add corrosion-rs (Rust ↔ CMake bridge for uno/plonky3-ffi)")
  # Rust .a will be linked into the uno_workchain static lib which in turn
  # feeds shared libs downstream; force PIC on the Rust side to avoid
  # "relocation R_X86_64_32 against .rodata" link errors on GNU/Linux.
  set(ENV{CARGO_PROFILE_RELEASE_PIC} "true")
  set(ENV{CARGO_PROFILE_DEV_PIC} "true")
  # Corrosion's own test suite is off when consumed as a subproject, but be
  # explicit so a future top-level rebase doesn't flip the default on us.
  set(CORROSION_BUILD_TESTS OFF CACHE BOOL "" FORCE)
  add_subdirectory(third-party/corrosion EXCLUDE_FROM_ALL)
endif()

if (USE_EMSCRIPTEN OR EMSCRIPTEN)
  set(SODIUM_ROOT_DIR ${CMAKE_BINARY_DIR}/3pp_emscripten/libsodium CACHE PATH "Sodium root directory" FORCE)
  if (EXISTS ${SODIUM_ROOT_DIR}/lib/libsodium.a)
    set(SODIUM_LIBRARY_PATH ${SODIUM_ROOT_DIR}/lib/libsodium.a)
    set(SODIUM_INCLUDE_PATH ${SODIUM_ROOT_DIR}/include)
  else()
    set(SODIUM_LIBRARY_PATH ${SODIUM_ROOT_DIR}/src/libsodium/.libs/libsodium.a)
    set(SODIUM_INCLUDE_PATH ${SODIUM_ROOT_DIR}/src/libsodium/include)
  endif()
  set(SODIUM_LIBRARY_RELEASE ${SODIUM_LIBRARY_PATH} CACHE FILEPATH "Sodium release library" FORCE)
  set(SODIUM_LIBRARY_DEBUG ${SODIUM_LIBRARY_PATH} CACHE FILEPATH "Sodium debug library" FORCE)
  set(SODIUM_INCLUDE_DIR ${SODIUM_INCLUDE_PATH} CACHE PATH "Sodium include directory" FORCE)
  set(SODIUM_FOUND TRUE CACHE BOOL "Sodium found" FORCE)
endif()

#message("Add OpenSSL")
#add_subdirectory(third-party/openssl EXCLUDE_FROM_ALL)

if (TOS_USE_ROCKSDB)
  message("Add rocksdb")
  function(rocksdb_scope)
    if (ANDROID)
      set(PORTABLE ON CACHE BOOL "")
    endif()
    set(WITH_GFLAGS OFF CACHE BOOL "")
    set(WITH_TESTS OFF CACHE BOOL "")
    set(WITH_TOOLS OFF CACHE BOOL "")
    set(USE_RTTI ON CACHE BOOL "")
    set(FAIL_ON_WARNINGS OFF CACHE BOOL "")
    set(WITH_ASAN ${TOS_USE_ASAN} CACHE BOOL "")
    set(WITH_TSAN ${TOS_USE_TSAN} CACHE BOOL "")
    set(WITH_UBSAN ${TOS_USE_UBSAN} CACHE BOOL "")
    add_subdirectory(third-party/rocksdb EXCLUDE_FROM_ALL)
    # Broken CMake in rocksdb alters properties it has no business changing.
    set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE)
    set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK)
  endfunction()
  rocksdb_scope()
endif()

if (TOS_USE_ASAN)
  add_compile_options(-fsanitize=address)
  add_link_options(-fsanitize=address)
  add_definitions(-DTD_USE_ASAN=1)
endif()
if (TOS_USE_TSAN)
  add_compile_options(-fsanitize=thread)
  add_link_options(-fsanitize=thread)
endif()
if (TOS_USE_UBSAN)
  add_compile_options(-fsanitize=undefined)
  add_link_options(-fsanitize=undefined)
endif()

if (TOS_USE_ABSEIL)
  message("Add abseil-cpp")
  function(abseil_scope)
    set(ABSL_PROPAGATE_CXX_STD TRUE)
    set(CMAKE_POLICY_VERSION_MINIMUM "3.10")
    add_subdirectory(third-party/abseil-cpp EXCLUDE_FROM_ALL)
  endfunction()
  abseil_scope()
  set(ABSL_FOUND 1)
endif()

if (WIN32)
  message("Add wingetopt")
  function(wingetopt_scope)
    set(CMAKE_POLICY_VERSION_MINIMUM "3.10")
    add_subdirectory(third-party/wingetopt EXCLUDE_FROM_ALL)
  endfunction()
  wingetopt_scope()
  set(WINGETOPT_FOUND 1)
endif()

set(CRC32C_BUILD_TESTS OFF CACHE BOOL "Build CRC32C's unit tests")
set(CRC32C_BUILD_BENCHMARKS OFF CACHE BOOL "Build CRC32C's benchmarks")
set(CRC32C_USE_GLOG OFF CACHE BOOL "Build CRC32C's tests with Google Logging")
set(CRC32C_INSTALL OFF CACHE BOOL "Install CRC32C's header and library")
message("Add crc32c")
function(crc32_scope)
  set(CMAKE_POLICY_VERSION_MINIMUM "3.10")
  if (NOT MSVC)
    # fix aarch64 build @ crc32c/src/crc32c_arm64_linux_check.h
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-error=address")
  endif()
  add_subdirectory(third-party/crc32c EXCLUDE_FROM_ALL)
endfunction()
crc32_scope()
set(CRC32C_FOUND 1)

option(USE_LIBRAPTORQ "use libraptorq for tests" OFF)
if (USE_LIBRAPTORQ)
  set(USE_LZ4 OFF CACHE BOOL "use lz4")
  if (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    set(CLANG_STDLIB "ON") # for libraptorq
  endif()
  message("Add libraptorq")
  add_subdirectory(third-party/libraptorq EXCLUDE_FROM_ALL)
endif()

option(USE_QUIC "use ngtcp2 QUIC library" ON)
if (USE_QUIC)
  # Set OpenSSL paths to use our custom-built OpenSSL with QUIC support
  # Use CACHE variables to override find_package(OpenSSL) behavior
  if (USE_EMSCRIPTEN OR EMSCRIPTEN)
    set(OPENSSL_ROOT_DIR ${CMAKE_BINARY_DIR}/3pp_emscripten/openssl_em CACHE PATH "OpenSSL root directory" FORCE)
    set(OPENSSL_INCLUDE_DIR ${OPENSSL_ROOT_DIR}/include CACHE PATH "OpenSSL include directory" FORCE)
    set(OPENSSL_CRYPTO_LIBRARY ${OPENSSL_ROOT_DIR}/libcrypto.a CACHE FILEPATH "OpenSSL crypto library" FORCE)
    set(OPENSSL_SSL_LIBRARY ${OPENSSL_ROOT_DIR}/libssl.a CACHE FILEPATH "OpenSSL SSL library" FORCE)
  elseif (ANDROID)
    include(AndroidThirdParty)
    set(OPENSSL_ROOT_DIR ${CMAKE_BINARY_DIR}/third-party/openssl-android-${TOS_ANDROID_OPENSSL_DIR} CACHE PATH "OpenSSL root directory" FORCE)
    set(OPENSSL_INCLUDE_DIR ${OPENSSL_ROOT_DIR}/include CACHE PATH "OpenSSL include directory" FORCE)
    set(OPENSSL_CRYPTO_LIBRARY ${OPENSSL_ROOT_DIR}/libcrypto.a CACHE FILEPATH "OpenSSL crypto library" FORCE)
    set(OPENSSL_SSL_LIBRARY ${OPENSSL_ROOT_DIR}/libssl.a CACHE FILEPATH "OpenSSL SSL library" FORCE)
  elseif (MSVC)
    set(OPENSSL_ROOT_DIR ${CMAKE_BINARY_DIR}/third-party/openssl CACHE PATH "OpenSSL root directory" FORCE)
    set(OPENSSL_INCLUDE_DIR ${OPENSSL_ROOT_DIR}/include CACHE PATH "OpenSSL include directory" FORCE)
    set(OPENSSL_CRYPTO_LIBRARY ${OPENSSL_ROOT_DIR}/lib/libcrypto.lib CACHE FILEPATH "OpenSSL crypto library" FORCE)
    set(OPENSSL_SSL_LIBRARY ${OPENSSL_ROOT_DIR}/lib/libssl.lib CACHE FILEPATH "OpenSSL SSL library" FORCE)
  else()
    set(OPENSSL_ROOT_DIR ${CMAKE_BINARY_DIR}/third-party/openssl CACHE PATH "OpenSSL root directory" FORCE)
    set(OPENSSL_INCLUDE_DIR ${CMAKE_BINARY_DIR}/third-party/openssl/include CACHE PATH "OpenSSL include directory" FORCE)
    set(OPENSSL_CRYPTO_LIBRARY ${CMAKE_BINARY_DIR}/third-party/openssl/lib/libcrypto.a CACHE FILEPATH "OpenSSL crypto library" FORCE)
    set(OPENSSL_SSL_LIBRARY ${CMAKE_BINARY_DIR}/third-party/openssl/lib/libssl.a CACHE FILEPATH "OpenSSL SSL library" FORCE)
  endif()
  set(OPENSSL_LIBRARIES ${OPENSSL_SSL_LIBRARY} ${OPENSSL_CRYPTO_LIBRARY} ${CMAKE_DL_LIBS} ${CMAKE_THREAD_LIBS_INIT}
    CACHE STRING "OpenSSL libraries" FORCE)
  if (MSVC)
    set(OPENSSL_LIBRARIES ${OPENSSL_LIBRARIES} crypt32 CACHE STRING "OpenSSL libraries" FORCE)
  endif()
  set(OPENSSL_FOUND TRUE CACHE BOOL "OpenSSL found" FORCE)

  function(ngtcp2_scope)
    set(BUILD_TESTING OFF)
    message("Add ngtcp2 with custom OpenSSL from ${OPENSSL_ROOT_DIR}")
    if (MINGW)
      # Assume QUIC support for the custom OpenSSL to avoid MSYS2 patching issues.
      set(HAVE_SSL_SET_QUIC_TLS_CBS TRUE CACHE BOOL "OpenSSL QUIC support" FORCE)
    endif()
    add_subdirectory(third-party/ngtcp2 EXCLUDE_FROM_ALL)
    set(NGTCP2_ROOT ${CMAKE_SOURCE_DIR}/third-party/ngtcp2)
  endfunction()
  ngtcp2_scope()

  # Make sure ngtcp2 libraries depend on OpenSSL being built first
  add_dependencies(ngtcp2 OpenSSL)
  if (TARGET ngtcp2_crypto_quictls)
    add_dependencies(ngtcp2_crypto_quictls OpenSSL)
  endif()
endif ()

message("Add tl-parser")
add_subdirectory(third-party/tl-parser EXCLUDE_FROM_ALL)

message("Add tos")
include(BuildBLST)
include(BuildSECP256K1)
include(BuildLibbacktrace)
include(BuildMHD)
include(BuildZlib)

# --- EVM Workchain third-party dependencies ---
if (NOT TOS_ONLY_TOSLIB)
  message("Add EVM workchain dependencies (intx, ethash, evmone)")
  function(evm_deps_scope)
    # intx: extended precision integer library (header-only)
    add_subdirectory(third-party/intx EXCLUDE_FROM_ALL)
    # ethash: keccak hashing
    set(ETHASH_BUILD_GLOBAL_CONTEXT OFF CACHE BOOL "" FORCE)
    set(ETHASH_BUILD_ETHASH ON CACHE BOOL "" FORCE)
    set(ETHASH_TESTING OFF CACHE BOOL "" FORCE)
    add_subdirectory(third-party/ethash EXCLUDE_FROM_ALL)
    # evmone: EVM implementation (includes evmc)
    add_subdirectory(third-party/evmone EXCLUDE_FROM_ALL)
  endfunction()
  evm_deps_scope()

  # libff: finite field library for alt_bn128 pairing / modexp
  message("Add libff (alt_bn128 precompiles)")
  add_subdirectory(third-party/libff EXCLUDE_FROM_ALL)

  # silkworm-core: Ethereum execution types, state, EVM wrapper
  message("Add silkworm-core (Ethereum execution engine)")
  add_subdirectory(third-party/silkworm/core EXCLUDE_FROM_ALL)
endif()


# Configure CCache if available
find_program(CCACHE_FOUND ccache)
if (CCACHE_FOUND)
  if (NOT DEFINED CMAKE_C_COMPILER_LAUNCHER AND NOT DEFINED CMAKE_CXX_COMPILER_LAUNCHER)
    message(STATUS "Using ccache")
    set(CMAKE_C_COMPILER_LAUNCHER ccache)
    set(CMAKE_CXX_COMPILER_LAUNCHER ccache)
  endif()
else()
  message(STATUS "Could NOT find ccache")
endif()

include(CheckCXXCompilerFlag)

set(CMAKE_THREAD_PREFER_PTHREAD ON)
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
find_package(PkgConfig REQUIRED)

if (MINGW)
  option(TOS_USE_STATIC_ZLIB "Prefer static zlib on MinGW to avoid runtime DLLs" ON)
  if (TOS_USE_STATIC_ZLIB)
    set(ZLIB_USE_STATIC_LIBS ON)
  endif()
endif()

if (NOT ZLIB_FOUND)
  find_package(ZLIB REQUIRED)
  if (MINGW AND TOS_USE_STATIC_ZLIB AND ZLIB_LIBRARY MATCHES "\\.dll\\.a$")
    get_filename_component(_zlib_lib_dir "${ZLIB_LIBRARY}" DIRECTORY)
    if (EXISTS "${_zlib_lib_dir}/libz.a")
      set(ZLIB_LIBRARY "${_zlib_lib_dir}/libz.a" CACHE FILEPATH "Zlib library" FORCE)
      set(ZLIB_LIBRARIES "${ZLIB_LIBRARY}" CACHE STRING "Zlib libraries" FORCE)
    endif()
    unset(_zlib_lib_dir)
  endif()
else()
  message(STATUS "Using zlib ${ZLIB_LIBRARIES}")
endif()


if (TOS_ARCH AND NOT MSVC)
  CHECK_CXX_COMPILER_FLAG( "-march=${TOS_ARCH}" COMPILER_OPT_ARCH_SUPPORTED )
  if (TOS_ARCH STREQUAL "apple-m1")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mcpu=${TOS_ARCH}")
  elseif(COMPILER_OPT_ARCH_SUPPORTED)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=${TOS_ARCH}")
  elseif(NOT TOS_ARCH STREQUAL "native")
    message(FATAL_ERROR "Compiler doesn't support arch ${TOS_ARCH}")
  endif()
endif()
if (THREADS_HAVE_PTHREAD_ARG)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
endif()

if (TOS_USE_JEMALLOC)
  find_package(jemalloc REQUIRED)
endif()

if (NIX)
  find_package(Secp256k1 REQUIRED)
endif()


set(MEMPROF "" CACHE STRING "Use one of \"ON\", \"FAST\" or \"SAFE\" to enable memory profiling. \
Works under macOS and Linux when compiled using glibc. \
In FAST mode stack is unwinded only using frame pointers, which may fail. \
In SAFE mode stack is unwinded using backtrace function from execinfo.h, which may be very slow. \
By default both methods are used to achieve maximum speed and accuracy")

if (CLANG OR GCC)
  if (MEMPROF)
    check_cxx_compiler_flag(-no-pie CXX_NO_PIE_FLAG)
    if (CXX_NO_PIE_FLAG)
      set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -no-pie")
    elseif (APPLE)
      set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-no_pie")
    endif()
  endif()
endif()

if (MSVC)
  if (CMAKE_CXX_FLAGS_DEBUG MATCHES "/RTC1")
    string(REPLACE "/RTC1" " " CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG}")
  endif()
  add_definitions(-D_SCL_SECURE_NO_WARNINGS -D_CRT_SECURE_NO_WARNINGS)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /MP /W4 /wd4100 /wd4127 /wd4324 /wd4456 /wd4457 /wd4458 /wd4505 /wd4702")
elseif (CLANG OR GCC)
  if (GCC)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fstrong-eval-order=some")
  endif()
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-omit-frame-pointer")
  if (APPLE)
    #use "-Wl,-exported_symbols_list,${CMAKE_CURRENT_SOURCE_DIR}/export_list" for exported symbols
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -fvisibility=hidden -Wl,-dead_strip,-x,-S")
    set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -fvisibility=hidden -Wl,-dead_strip,-x,-S")
    # Generate dSYM bundles for proper stack traces with libbacktrace (for Ninja/Make generators)
    if(NOT DSYMUTIL_LINK_CONFIGURED AND NOT CMAKE_GENERATOR MATCHES "Xcode" AND CMAKE_BUILD_TYPE MATCHES "Debug|RelWithDebInfo")
      set(DSYMUTIL_LINK_CONFIGURED TRUE CACHE INTERNAL "dSYM generation configured in linker")
      set(CMAKE_C_LINK_EXECUTABLE "${CMAKE_C_LINK_EXECUTABLE} && dsymutil <TARGET>")
      set(CMAKE_CXX_LINK_EXECUTABLE "${CMAKE_CXX_LINK_EXECUTABLE} && dsymutil <TARGET>")
    endif()
  else()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -ffunction-sections -fdata-sections")
    if (NOT USE_EMSCRIPTEN)
      set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--gc-sections")
      if (NOT MINGW)
        set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--exclude-libs,ALL")
      endif()
    endif()
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--gc-sections")
    if (NOT TOS_USE_ASAN AND NOT TOS_USE_TSAN AND NOT TOS_USE_COVERAGE AND NOT MEMPROF)
      if (NOT USE_EMSCRIPTEN)
        if (NOT MINGW)
          set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--exclude-libs,ALL")
        endif()
      endif()
    endif()
  endif()
endif()

if (WIN32)
  add_definitions(-DNTDDI_VERSION=0x06020000 -DWINVER=0x0602 -D_WIN32_WINNT=0x0602 -DNOMINMAX -DUNICODE -D_UNICODE)
endif()
if (CYGWIN)
  add_definitions(-D_DEFAULT_SOURCE=1 -DFD_SETSIZE=4096)
endif()

if (NOT ANDROID) # _FILE_OFFSET_BITS is broken in ndk r15 and r15b and doesn't work prior to Android 7.0
  add_definitions(-D_FILE_OFFSET_BITS=64)
endif()

if (TOS_INSERT_GDB_HOOKS)
  add_compile_definitions(-DTOS_INSERT_GDB_HOOKS=1)
endif()

set(INTERNAL_COMPILE "0")
#BEGIN internal
  add_definitions(-D_INTERNAL_COMPILE=1)
  set(INTERNAL_COMPILE "1")
#END internal

set(TOSLIB_COMPILE "0")
#BEGIN toslib
  add_definitions(-D_TOSLIB_COMPILE=1)
  set(TOSLIB_COMPILE "1")
#END toslib

if (MSVC)
  add_compile_options(/experimental:external /external:anglebrackets /external:W0)
endif()

if (GCC OR CLANG)
  add_compile_options(-Wall)
  add_compile_options(-Wextra)

  add_compile_options(-Wpointer-arith)
  add_compile_options(-Wcast-qual)
  add_compile_options(-Wsign-compare)
  add_compile_options(-Wpointer-arith)
  add_compile_options(-Wvla)
  add_compile_options(-Wnon-virtual-dtor)
  add_compile_options(-Wconversion)

  # TODO: Either justify all of these or remove.
  add_compile_options(-Wno-tautological-compare)
  add_compile_options(-Wno-unused-parameter)
  add_compile_options(-Wno-sign-conversion)
  add_compile_options(-Wno-unused-private-field)
  add_compile_options(-Wno-redundant-move)

  if (GCC)
    add_compile_options(-Wimplicit-fallthrough=2)
    add_compile_options(-Wduplicated-branches)
    add_compile_options(-Wduplicated-cond)
    add_compile_options(-Walloc-zero)
    add_compile_options(-Wlogical-op)
  endif()
endif()

if (GCC OR CLANG)
  if (CMAKE_BUILD_TYPE MATCHES "RelWithDebInfo")
    # For historical reasons, CMake falls back to -O2 optimization level when CMAKE_BUILD_TYPE is
    # set to RelWithDebInfo.
    add_compile_options(-O3)
  endif()
endif()

if (TOS_USE_COVERAGE)
  add_cxx_compiler_flag("-fprofile-arcs")
  add_cxx_compiler_flag("-ftest-coverage")
  add_cxx_compiler_flag("--coverage")
  add_cxx_compiler_flag("-O0")
  add_cxx_compiler_flag("-g")
  add_cxx_compiler_flag("-fno-inline")
  add_cxx_compiler_flag("-fno-inline-small-functions")
  add_cxx_compiler_flag("-fno-default-inline")
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fprofile-arcs -ftest-coverage --coverage")
  set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -fprofile-arcs -ftest-coverage --coverage")
endif()
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=thread")
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address")
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=undefined")
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=leak")
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -finstrument-functions")

#Compilation database
set(CMAKE_EXPORT_COMPILE_COMMANDS 1)

#BEGIN internal
option(TOS_BUILD_DOCS "Build LaTeX/PDF documentation targets" OFF)
find_package(LATEX)
if (TOS_BUILD_DOCS AND LATEX_FOUND)
  include(UseLATEX)
  add_latex_document(doc/tvm.tex TARGET_NAME tos_vm_description)
  add_latex_document(doc/tblkch.tex TARGET_NAME tos_blockchain_description)
  add_latex_document(doc/fiftbase.tex TARGET_NAME fift_basic_description)
  add_latex_document(doc/catchain.tex TARGET_NAME catchain_consensus_description)
elseif (TOS_BUILD_DOCS)
  message(STATUS "Could NOT find LATEX (this is NOT an error)")
endif()
#END internal

if (NOT OPENSSL_FOUND)
  find_package(OpenSSL REQUIRED)
endif()

function(target_link_libraries_system target)
  set(libs ${ARGN})
  foreach(lib ${libs})
    get_target_property(lib_include_dirs ${lib} INTERFACE_INCLUDE_DIRECTORIES)
    target_include_directories(${target} SYSTEM PUBLIC ${lib_include_dirs})
    target_link_libraries(${target} PUBLIC ${lib})
  endforeach(lib)
endfunction(target_link_libraries_system)

add_custom_target(all-tests)

function(tos_test TEST_NAME)
  add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME} ${ARGN})
  add_dependencies(all-tests ${TEST_NAME})
endfunction()

enable_testing()

set(TDUTILS_MIME_TYPE OFF CACHE BOOL "Generate mime type conversion")
add_subdirectory(tdutils)
if (TARGET lz4 AND TARGET tdutils)
  add_dependencies(tdutils lz4)
endif()
add_subdirectory(memprof)
add_subdirectory(metrics)
add_subdirectory(tdactor)
add_subdirectory(tdnet)
if (TOS_USE_ROCKSDB)
  option(TDDB_USE_ROCKSDB "Use rockdb" ON)
endif()
add_subdirectory(tddb)
add_subdirectory(tdtl)
add_subdirectory(tl)
add_subdirectory(terminal)
add_subdirectory(keys)
add_subdirectory(tl-utils)
add_subdirectory(adnl)
add_subdirectory(crypto)
if (NOT TOS_ONLY_TOSLIB)
  add_subdirectory(evm)
endif()
if (NOT TOS_ONLY_TOSLIB)
  add_subdirectory(uno)
endif()
add_subdirectory(lite-client)
add_subdirectory(emulator)
add_subdirectory(tol)

#BEGIN toslib
add_subdirectory(toslib)
#END toslib

# Temporary (?) move those two targets in TOSLIB targets
add_subdirectory(common)
add_subdirectory(http)

#BEGIN internal
if (NOT TOS_ONLY_TOSLIB)
add_subdirectory(tdfec)
add_subdirectory(keyring)
add_subdirectory(fec)
add_subdirectory(rldp)
add_subdirectory(rldp2)
add_subdirectory(dht)
add_subdirectory(overlay)
add_subdirectory(catchain)
add_subdirectory(validator-session)
add_subdirectory(validator)
if (NOT USE_EMSCRIPTEN AND NOT EMSCRIPTEN)
  add_subdirectory(blockchain-explorer)
endif()
add_subdirectory(storage)
add_subdirectory(validator-engine)
add_subdirectory(validator-engine-console)
add_subdirectory(create-hardfork)
add_subdirectory(dht-server)
add_subdirectory(utils)
add_subdirectory(rldp-http-proxy)
endif()
#END internal

if (USE_QUIC)
  add_subdirectory(quic)
endif ()

if (NOT CMAKE_CROSSCOMPILING)
  if (TDUTILS_MIME_TYPE)
    set(TDMIME_AUTO tdmime_auto)
  endif()
  add_custom_target(prepare_cross_compiling DEPENDS tl_generate_common tlb_generate_block gen_fif ${TDMIME_AUTO})
endif()

#TESTS
add_executable(test-ed25519 test/test-td-main.cpp ${ED25519_TEST_SOURCE})
target_link_libraries(test-ed25519 PRIVATE tos_crypto)

add_executable(test-vm test/test-td-main.cpp ${TOSVM_TEST_SOURCE})
target_link_libraries(test-vm PRIVATE tos_crypto fift-lib)

add_executable(test-smartcont test/test-td-main.cpp ${SMARTCONT_TEST_SOURCE})
target_link_libraries(test-smartcont PRIVATE smc-envelope fift-lib tos_db)
add_dependencies(test-smartcont create-state)

add_executable(test-bigint ${BIGINT_TEST_SOURCE})
target_link_libraries(test-bigint PRIVATE tos_crypto)

if (WINGETOPT_FOUND)
  target_link_libraries_system(test-bigint wingetopt)
endif()

add_executable(test-cells test/test-td-main.cpp ${CELLS_TEST_SOURCE})
target_link_libraries(test-cells PRIVATE tos_crypto)

add_executable(test-fift test/test-td-main.cpp ${FIFT_TEST_SOURCE})
target_link_libraries(test-fift PRIVATE fift-lib)

add_executable(test-tdutils test/test-td-main.cpp ${TDUTILS_TEST_SOURCE})
target_link_libraries(test-tdutils PRIVATE tdutils ${CMAKE_THREAD_LIBS_INIT} memprof ${JEMALLOC_LIBRARIES})

add_executable(test-tdactor test/test-td-main.cpp ${TDACTOR_TEST_SOURCE})
target_link_libraries(test-tdactor PRIVATE tdactor ${CMAKE_THREAD_LIBS_INIT})

add_executable(test-net test/test-td-main.cpp ${NET_TEST_SOURCE})
target_link_libraries(test-net PRIVATE tdnet tdutils ${CMAKE_THREAD_LIBS_INIT})

#BEGIN toslib
add_executable(test-toslib ${TOSLIB_ONLINE_TEST_SOURCE})
target_link_libraries(test-toslib tdactor adnllite tl_api tos_crypto tl_toslib_api toslib)

add_executable(test-toslib-offline test/test-td-main.cpp ${TOSLIB_OFFLINE_TEST_SOURCE})
target_link_libraries(test-toslib-offline tdactor adnllite tl_api tos_crypto fift-lib tl_toslib_api toslib)

if (NOT CMAKE_CROSSCOMPILING)
  add_dependencies(test-toslib-offline gen_fif)
endif()
#END toslib

#BEGIN internal
if (NOT TOS_ONLY_TOSLIB)
add_executable(test-db test/test-td-main.cpp ${TOSDB_TEST_SOURCE})
target_link_libraries(test-db PRIVATE tos_db memprof tdfec)

add_executable(test-storage test/test-td-main.cpp ${STORAGE_TEST_SOURCE})
target_link_libraries(test-storage PRIVATE storage tos_db memprof tl_api tl-utils fec rldp2)

add_executable(test-rocksdb test/test-rocksdb.cpp)
target_link_libraries(test-rocksdb PRIVATE memprof tddb tdutils)

add_executable(test-tddb test/test-td-main.cpp ${TDDB_TEST_SOURCE})
target_link_libraries(test-tddb PRIVATE tdutils tddb ${CMAKE_THREAD_LIBS_INIT} memprof)

add_executable(test-fec test/test-td-main.cpp ${FEC_TEST_SOURCE})
target_link_libraries(test-fec PRIVATE tdfec tdutils ${CMAKE_THREAD_LIBS_INIT})
if (USE_LIBRAPTORQ)
  target_link_libraries(test-fec PRIVATE third_party_fec)
  target_compile_definitions(test-fec PRIVATE "USE_LIBRAPTORQ=1")
endif()

add_executable(test-hello-world test/test-hello-world.cpp )
target_link_libraries(test-hello-world tl_api tos_crypto)

add_executable(test-adnl test/test-adnl.cpp)
target_link_libraries(test-adnl adnl adnltest dht tl_api)
add_executable(test-dht test/test-dht.cpp)
target_link_libraries(test-dht adnl adnltest dht tl_api)
add_executable(test-rldp test/test-rldp.cpp)
target_link_libraries(test-rldp adnl adnltest dht rldp tl_api)
add_executable(test-rldp2 test/test-rldp2.cpp)
target_link_libraries(test-rldp2 adnl adnltest dht rldp2 tl_api)
add_executable(bench-rldp test/net/bench-rldp.cpp)
target_link_libraries(bench-rldp adnl adnltest dht rldp rldp2 tl_api quic metrics)
add_executable(test-quic-sender test/net/test-quic-sender.cpp)
target_link_libraries(test-quic-sender adnl dht tl_api quic)
add_executable(test-validator-session-state test/test-validator-session-state.cpp)
target_link_libraries(test-validator-session-state adnl dht rldp validatorsession tl_api)
add_executable(test-quorum test/test-quorum.cpp)
target_link_libraries(test-quorum tos_block tdutils)
add_test(
  NAME test-quorum-static-grep
  COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check-quorum-static.sh
          ${CMAKE_CURRENT_SOURCE_DIR})
add_test(
  NAME test-evm-production-hardening-static
  COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check-evm-production-hardening.sh
          ${CMAKE_CURRENT_SOURCE_DIR})
set(TOS_SOLC_0_8_26 "" CACHE FILEPATH "Pinned solc 0.8.26 binary for EToSPoWGiver bytecode equivalence")
if(TOS_SOLC_0_8_26)
  add_test(
    NAME test-evm-etos-giver-bytecode-equivalence
    COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check-evm-production-hardening.sh
            ${CMAKE_CURRENT_SOURCE_DIR})
  set_tests_properties(test-evm-etos-giver-bytecode-equivalence
    PROPERTIES ENVIRONMENT "TOS_CHECK_ETOS_GIVER_BYTECODE=1;TOS_SOLC_0_8_26=${TOS_SOLC_0_8_26}")
endif()

add_executable(test-overlay test/test-overlay.cpp)
target_link_libraries(test-overlay overlay tdutils tdactor adnl adnltest tl_api dht )
add_executable(test-catchain test/test-catchain.cpp)
target_link_libraries(test-catchain overlay tdutils tdactor adnl adnltest rldp tl_api dht
  catchain )
add_executable(test-tos-collator test/test-tos-collator.cpp)
target_link_libraries(test-tos-collator overlay tdutils tdactor adnl tl_api dht
  catchain validatorsession validator-disk tos_validator validator-disk )

add_executable(test-download-state-budget test/test-download-state-budget.cpp)
# Link tos_crypto for vm::std_boc_serialize / std_boc_deserialize, used by
# the OnDisk corruption regression to assemble a known-good shard-state BoC
# and verify that the BoC layer + root-hash compare reject every flavor of
# tempfile corruption (mid-payload byte flip, CRC32C trailer wipe, content
# swap with valid BoC envelope).
target_link_libraries(test-download-state-budget PRIVATE validator-common full-node tos_crypto tdutils tdactor adnl overlay tl_api dht)

# Phase B Step 8 — five invariant regression tests for the true
# CellDb-backed streaming importer (replacement-hash equality, no
# full-DAG residency, crash/abort no partial state, lazy load, hash
# mismatch). Links the same surfaces test-download-state-budget pulls
# (validator-common drags in the streaming sink + parse helper;
# tos_db drags in MemoryKeyValue + CellStorer; tos_crypto carries
# CellDbExtCell + DynamicBagOfCellsDb).
add_executable(test-celldb-streaming-import test/test-celldb-streaming-import.cpp)
target_link_libraries(test-celldb-streaming-import PRIVATE validator-common validator-db full-node tos_db tos_crypto tdutils tdactor adnl overlay tl_api dht)

add_executable(test-celldb-actor-restart test/test-celldb-actor-restart.cpp)
target_link_libraries(test-celldb-actor-restart PRIVATE validator-common validator-db full-node tos_db tos_crypto tdutils tdactor adnl overlay tl_api dht)

add_executable(test-http test/test-http.cpp)
target_link_libraries(test-http PRIVATE toshttp)

# Slice 1 Stage 4 gas-parity harness — pre-compile the migrated reference
# contracts (.fc and .tol) into .boc files so the runtime fixture in
# emulator/test/slice-1-stage-4-gas-parity-fixture.cpp can read them via
# td::read_file rather than shelling out to func/tol/fift at test time.
# Closes the §4 closure spec in doc/slice-1-gas-gap.md.
set(SLICE1_GAS_PARITY_DIR ${CMAKE_CURRENT_BINARY_DIR}/slice1-gas-parity)
file(MAKE_DIRECTORY ${SLICE1_GAS_PARITY_DIR})

# Compile a .tol source to a .boc. Tol's --boc-output emits the BoC
# write directive into its .fif output; running fift on that .fif then
# materializes the .boc on disk.
function(slice1_tol_to_boc TOL_SOURCE OUT_BOC)
    get_filename_component(_stem ${OUT_BOC} NAME_WE)
    set(_fif ${SLICE1_GAS_PARITY_DIR}/${_stem}.fif)
    add_custom_command(
        OUTPUT ${OUT_BOC}
        COMMAND ${CMAKE_COMMAND} -E env FIFTPATH=${CMAKE_CURRENT_SOURCE_DIR}/crypto/fift/lib
                $<TARGET_FILE:tol> --boc-output ${OUT_BOC} -o ${_fif} ${TOL_SOURCE}
        COMMAND ${CMAKE_COMMAND} -E env FIFTPATH=${CMAKE_CURRENT_SOURCE_DIR}/crypto/fift/lib
                $<TARGET_FILE:fift> ${_fif}
        WORKING_DIRECTORY ${SLICE1_GAS_PARITY_DIR}
        DEPENDS tol fift ${TOL_SOURCE}
        COMMENT "Compiling Tol contract ${_stem} -> ${OUT_BOC}"
        VERBATIM
    )
endfunction()

# Compile FunC sources (one or more .fc files) to a .boc. func -W emits
# the BoC write directive into its .fif output; running fift on that .fif
# materializes the .boc on disk.
function(slice1_func_to_boc OUT_BOC WORKING_DIR)
    get_filename_component(_stem ${OUT_BOC} NAME_WE)
    set(_fif ${SLICE1_GAS_PARITY_DIR}/${_stem}.fif)
    set(_sources ${ARGN})
    add_custom_command(
        OUTPUT ${OUT_BOC}
        COMMAND ${CMAKE_COMMAND} -E env FIFTPATH=${CMAKE_CURRENT_SOURCE_DIR}/crypto/fift/lib
                $<TARGET_FILE:func> -W ${OUT_BOC} -A -P -o ${_fif} ${_sources}
        COMMAND ${CMAKE_COMMAND} -E env FIFTPATH=${CMAKE_CURRENT_SOURCE_DIR}/crypto/fift/lib
                $<TARGET_FILE:fift> ${_fif}
        WORKING_DIRECTORY ${WORKING_DIR}
        DEPENDS func fift ${_sources}
        COMMENT "Compiling FunC contract ${_stem} -> ${OUT_BOC}"
        VERBATIM
    )
endfunction()

set(SLICE1_GAS_PARITY_JETTON_MINTER_FUNC_BOC ${SLICE1_GAS_PARITY_DIR}/jetton-minter-func.boc)
set(SLICE1_GAS_PARITY_JETTON_MINTER_TOL_BOC  ${SLICE1_GAS_PARITY_DIR}/jetton-minter-tol.boc)
set(SLICE1_GAS_PARITY_JETTON_WALLET_FUNC_BOC ${SLICE1_GAS_PARITY_DIR}/jetton-wallet-func.boc)
set(SLICE1_GAS_PARITY_JETTON_WALLET_TOL_BOC  ${SLICE1_GAS_PARITY_DIR}/jetton-wallet-tol.boc)
set(SLICE1_GAS_PARITY_WALLET_V5_FUNC_BOC     ${SLICE1_GAS_PARITY_DIR}/wallet-v5-func.boc)
set(SLICE1_GAS_PARITY_WALLET_V5_TOL_BOC      ${SLICE1_GAS_PARITY_DIR}/wallet-v5-tol.boc)
set(SLICE5_RECEIVE_CONTEXT_TOL_BOC            ${SLICE1_GAS_PARITY_DIR}/slice5-receive-context-tol.boc)
set(TOS_REPORT_BOND_ORACLE_BOC                ${SLICE1_GAS_PARITY_DIR}/tos-report-bond-oracle.boc)

slice1_tol_to_boc(${CMAKE_CURRENT_SOURCE_DIR}/crypto/smartcont/jetton-minter.tol
                  ${SLICE1_GAS_PARITY_JETTON_MINTER_TOL_BOC})
slice1_tol_to_boc(${CMAKE_CURRENT_SOURCE_DIR}/crypto/smartcont/jetton-wallet.tol
                  ${SLICE1_GAS_PARITY_JETTON_WALLET_TOL_BOC})
slice1_tol_to_boc(${CMAKE_CURRENT_SOURCE_DIR}/crypto/smartcont/wallet-v5.tol
                  ${SLICE1_GAS_PARITY_WALLET_V5_TOL_BOC})
slice1_tol_to_boc(${CMAKE_CURRENT_SOURCE_DIR}/emulator/test/slice-5-receive-context.tol
                  ${SLICE5_RECEIVE_CONTEXT_TOL_BOC})
slice1_tol_to_boc(${CMAKE_CURRENT_SOURCE_DIR}/examples/slice5/tos-report-bond-oracle/src/tos-report-bond-oracle.tol
                  ${TOS_REPORT_BOND_ORACLE_BOC})

slice1_func_to_boc(${SLICE1_GAS_PARITY_JETTON_MINTER_FUNC_BOC}
                   ${CMAKE_CURRENT_SOURCE_DIR}/crypto/func/auto-tests/legacy_tests/jetton-minter
                   ${CMAKE_CURRENT_SOURCE_DIR}/crypto/func/auto-tests/legacy_tests/jetton-minter/jetton-minter.fc)
slice1_func_to_boc(${SLICE1_GAS_PARITY_JETTON_WALLET_FUNC_BOC}
                   ${CMAKE_CURRENT_SOURCE_DIR}/crypto/func/auto-tests/legacy_tests/jetton-wallet
                   ${CMAKE_CURRENT_SOURCE_DIR}/crypto/func/auto-tests/legacy_tests/jetton-wallet/jetton-wallet.fc)
# wallet-v5 lives at crypto/smartcont/wallet-v5-code.fc per the
# migration playbook (verified via the find search in this slice's
# closure work). It depends on crypto/smartcont/stdlib.fc, which is
# passed first so its #pragma version >=0.4.4 declarations are in
# scope when the contract sources are parsed.
slice1_func_to_boc(${SLICE1_GAS_PARITY_WALLET_V5_FUNC_BOC}
                   ${CMAKE_CURRENT_SOURCE_DIR}/crypto/smartcont
                   ${CMAKE_CURRENT_SOURCE_DIR}/crypto/smartcont/stdlib.fc
                   ${CMAKE_CURRENT_SOURCE_DIR}/crypto/smartcont/wallet-v5-code.fc)

add_custom_target(slice1_gas_parity_contracts ALL
    DEPENDS
        ${SLICE1_GAS_PARITY_JETTON_MINTER_FUNC_BOC}
        ${SLICE1_GAS_PARITY_JETTON_MINTER_TOL_BOC}
        ${SLICE1_GAS_PARITY_JETTON_WALLET_FUNC_BOC}
        ${SLICE1_GAS_PARITY_JETTON_WALLET_TOL_BOC}
        ${SLICE1_GAS_PARITY_WALLET_V5_FUNC_BOC}
        ${SLICE1_GAS_PARITY_WALLET_V5_TOL_BOC}
)

add_custom_target(slice5_receive_context_contract
    DEPENDS
        ${SLICE5_RECEIVE_CONTEXT_TOL_BOC}
)

add_custom_target(tos_report_bond_oracle_contract
    DEPENDS
        ${TOS_REPORT_BOND_ORACLE_BOC}
)

add_executable(test-emulator
        test/test-td-main.cpp
        emulator/test/emulator-tests.cpp
        # Slice 1 conformance fixtures (doc/roadmap.md Stage 1 exit criterion +
        # doc/tos-message-policy.md v6 §3.4 / §6.2 / §10.1).
        emulator/test/slice-1-account-state-fixtures.cpp
        emulator/test/slice-1-failure-phase-fixtures.cpp
        emulator/test/slice-1-extra-flags-fixtures.cpp
        emulator/test/slice-1-boc-envelope-fuzz-fixture.cpp
        emulator/test/slice-1-stage-2-roundtrip-fixture.cpp
        # Slice 1 Stage 4 gas-parity harness (closes doc/slice-1-gas-gap.md
        # §4; reads the .boc files materialized by the
        # slice1_gas_parity_contracts target above).
        emulator/test/slice-1-stage-4-gas-parity-fixture.cpp
        # Slice 3 Stage 1 deterministic replay harness (doc/tos-slice-3-policy.md).
        emulator/test/slice-3-replay-fixture.cpp
        # Slice 6 Stage 1 delivery-SLA canonical cell-shape fixtures.
        emulator/test/slice-6-stage1-delivery-fixtures.cpp
        # Slice 6 Stage 2 scheduled-message predicate fixtures.
        emulator/test/slice-6-stage2-schedule-fixtures.cpp
        # Slice 5 receive-context harness for production receive handlers.
        emulator/test/slice-5-receive-context-fixture.cpp
        emulator/test/tos-report-bond-oracle-fixture.cpp)
target_link_libraries(test-emulator PRIVATE emulator fift-lib)
add_dependencies(test-emulator slice1_gas_parity_contracts slice5_receive_context_contract tos_report_bond_oracle_contract)
target_compile_definitions(test-emulator PRIVATE
    SLICE1_GAS_PARITY_JETTON_MINTER_FUNC_BOC="${SLICE1_GAS_PARITY_JETTON_MINTER_FUNC_BOC}"
    SLICE1_GAS_PARITY_JETTON_MINTER_TOL_BOC="${SLICE1_GAS_PARITY_JETTON_MINTER_TOL_BOC}"
    SLICE1_GAS_PARITY_JETTON_WALLET_FUNC_BOC="${SLICE1_GAS_PARITY_JETTON_WALLET_FUNC_BOC}"
    SLICE1_GAS_PARITY_JETTON_WALLET_TOL_BOC="${SLICE1_GAS_PARITY_JETTON_WALLET_TOL_BOC}"
    SLICE1_GAS_PARITY_WALLET_V5_FUNC_BOC="${SLICE1_GAS_PARITY_WALLET_V5_FUNC_BOC}"
    SLICE1_GAS_PARITY_WALLET_V5_TOL_BOC="${SLICE1_GAS_PARITY_WALLET_V5_TOL_BOC}"
    SLICE5_RECEIVE_CONTEXT_TOL_BOC="${SLICE5_RECEIVE_CONTEXT_TOL_BOC}"
    TOS_REPORT_BOND_ORACLE_BOC="${TOS_REPORT_BOND_ORACLE_BOC}"
)

get_directory_property(HAS_PARENT PARENT_DIRECTORY)
if (HAS_PARENT)
  set(ALL_TEST_SOURCE
          ${TDUTILS_TEST_SOURCE}
          ${TDACTOR_TEST_SOURCE}
          ${NET_TEST_SOURCE}
          ${TDDB_TEST_SOURCE}
          ${FEC_TEST_SOURCE}
          ${ED25519_TEST_SOURCE}
          ${TOSDB_TEST_SOURCE}
          ${BIGNUM_TEST_SOURCE}
          ${CELLS_TEST_SOURCE}
          PARENT_SCOPE)
endif()
add_library(all_tests INTERFACE)
target_link_libraries(all_tests INTERFACE tdutils tdactor tdnet tdfec tos_db tos_crypto fift-lib)
endif()
#END internal

set(TEST_OPTIONS "--regression ${CMAKE_CURRENT_SOURCE_DIR}/test/regression-tests.ans --filter -Bench")
separate_arguments(TEST_OPTIONS)
tos_test(test-ed25519)
tos_test(test-bigint)
tos_test(test-vm ${TEST_OPTIONS})
tos_test(test-fift ${TEST_OPTIONS})
tos_test(test-cells ${TEST_OPTIONS})
tos_test(test-smartcont)
tos_test(test-net)
tos_test(test-tdactor)

#BEGIN toslib
tos_test(test-tdutils)
tos_test(test-toslib-offline)
#END toslib

# FunC tests
if (NOT NIX)
    if (MSVC)
      set(PYTHON_VER "python")
    else()
      set(PYTHON_VER "python3")
    endif()
    add_test(
      NAME test-func
      COMMAND ${PYTHON_VER} run_tests.py tests/
      WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/crypto/func/auto-tests)
    if (WIN32)
        set_property(TEST test-func PROPERTY ENVIRONMENT
          "FUNC_EXECUTABLE=${CMAKE_CURRENT_BINARY_DIR}/crypto/func.exe"
          "FIFT_EXECUTABLE=${CMAKE_CURRENT_BINARY_DIR}/crypto/fift.exe"
          "FIFTPATH=${CMAKE_CURRENT_SOURCE_DIR}/crypto/fift/lib/")
    else()
        set_property(TEST test-func PROPERTY ENVIRONMENT
          "FUNC_EXECUTABLE=${CMAKE_CURRENT_BINARY_DIR}/crypto/func"
          "FIFT_EXECUTABLE=${CMAKE_CURRENT_BINARY_DIR}/crypto/fift"
          "FIFTPATH=${CMAKE_CURRENT_SOURCE_DIR}/crypto/fift/lib/")
    endif()

    add_test(
      NAME test-func-legacy
      COMMAND ${PYTHON_VER} legacy_tester.py
      WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/crypto/func/auto-tests)
    if (WIN32)
        set_property(TEST test-func-legacy PROPERTY ENVIRONMENT
          "FUNC_EXECUTABLE=${CMAKE_CURRENT_BINARY_DIR}/crypto/func.exe"
          "FIFT_EXECUTABLE=${CMAKE_CURRENT_BINARY_DIR}/crypto/fift.exe"
          "FIFTPATH=${CMAKE_CURRENT_SOURCE_DIR}/crypto/fift/lib/")
    else()
        set_property(TEST test-func-legacy PROPERTY ENVIRONMENT
          "FUNC_EXECUTABLE=${CMAKE_CURRENT_BINARY_DIR}/crypto/func"
          "FIFT_EXECUTABLE=${CMAKE_CURRENT_BINARY_DIR}/crypto/fift"
          "FIFTPATH=${CMAKE_CURRENT_SOURCE_DIR}/crypto/fift/lib/")
    endif()
endif()

# Tol tests
if (NOT NIX)
    if (MSVC)
      set(PYTHON_VER "python")
    else()
      set(PYTHON_VER "python3")
    endif()
    add_test(
      NAME test-tol
      COMMAND ${PYTHON_VER} tol-tester.py tests/
      WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/tol-tester)
    if (WIN32)
        set_property(TEST test-tol PROPERTY ENVIRONMENT
          "TOL_EXECUTABLE=${CMAKE_CURRENT_BINARY_DIR}/tol/tol.exe"
          "FIFT_EXECUTABLE=${CMAKE_CURRENT_BINARY_DIR}/crypto/fift.exe"
          "FIFTPATH=${CMAKE_CURRENT_SOURCE_DIR}/crypto/fift/lib/")
    else()
        set_property(TEST test-tol PROPERTY ENVIRONMENT
          "TOL_EXECUTABLE=${CMAKE_CURRENT_BINARY_DIR}/tol/tol"
          "FIFT_EXECUTABLE=${CMAKE_CURRENT_BINARY_DIR}/crypto/fift"
          "FIFTPATH=${CMAKE_CURRENT_SOURCE_DIR}/crypto/fift/lib/")
    endif()
endif()

#BEGIN internal
if (NOT TOS_ONLY_TOSLIB)
tos_test(test-adnl)
tos_test(test-dht)
tos_test(test-rldp)
tos_test(test-rldp2)
tos_test(test-validator-session-state)
tos_test(test-download-state-budget)
tos_test(test-celldb-streaming-import)
tos_test(test-celldb-actor-restart)
tos_test(test-quorum)
tos_test(test-catchain)
tos_test(test-emulator)

tos_test(test-fec)
tos_test(test-tddb ${TEST_OPTIONS})
tos_test(test-db ${TEST_OPTIONS})

add_subdirectory(test)
endif()
#END internal
