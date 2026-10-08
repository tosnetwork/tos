# Client-only builds: the client toolchain without the node.
#
# TOS_CLIENT_ONLY=ON builds fift, func, tlbc, tol, lite-client, toslib,
# toslibjson, toslib-cli and the emulator, and leaves every node target
# undefined: the validator and its engine, the network stack above ADNL lite,
# storage, the proxies, the consensus and controller key tools and their
# key-file libraries, and the proof verifier. A request for one of those fails
# as an unknown target.
#
# Windows builds the client toolchain only. The node's key and configuration
# files rely on POSIX file semantics (owner checks, flock, directory fsync,
# no-follow opens) that have no ported equivalent, so on Windows the option is
# ON and an explicit OFF is refused rather than producing a node built on
# unported file handling. TOS_CLIENT_ONLY_ASSUME_WIN32 applies the Windows
# rule elsewhere so a test can check it.
#
# Must be included after project() and before TOS_ONLY_TOSLIB is evaluated.

set(_tos_client_only_platform OFF)
if(WIN32 OR TOS_CLIENT_ONLY_ASSUME_WIN32)
  set(_tos_client_only_platform ON)
endif()
if(_tos_client_only_platform AND DEFINED TOS_CLIENT_ONLY AND NOT TOS_CLIENT_ONLY)
  message(FATAL_ERROR "Windows supports the client toolchain only (TOS_CLIENT_ONLY=ON); "
    "node targets are not ported")
endif()
option(TOS_CLIENT_ONLY "Build the client toolchain only, without node targets"
  ${_tos_client_only_platform})
if(TOS_CLIENT_ONLY)
  # The client set is what the toslib-only build already defines; the node
  # tooling defined beside it is excluded where it is declared.
  set(TOS_ONLY_TOSLIB true)
endif()
unset(_tos_client_only_platform)
