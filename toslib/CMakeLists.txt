option(TOSLIBJSON_STATIC "Build toslibjson as static library" OFF)

set(TOSLIB_SOURCE
  toslib/Client.cpp
  toslib/Config.cpp
  toslib/EngineConsoleClient.cpp
  toslib/ExtClient.cpp
  toslib/ExtClientOutbound.cpp
  toslib/KeyStorage.cpp
  toslib/KeyValue.cpp
  toslib/LastBlock.cpp
  toslib/LastBlockStorage.cpp
  toslib/LastConfig.cpp
  toslib/Logging.cpp
  toslib/ToslibClient.cpp
  toslib/ToslibClientWrapper.cpp
  toslib/utils.cpp

  toslib/Client.h
  toslib/Config.h
  toslib/EngineConsoleClient.h
  toslib/ExtClient.h
  toslib/ExtClientOutbound.h
  toslib/KeyStorage.h
  toslib/KeyValue.h
  toslib/LastBlock.h
  toslib/LastBlockStorage.h
  toslib/LastConfig.h
  toslib/Logging.h
  toslib/ToslibCallback.h
  toslib/ToslibClient.h
  toslib/ToslibClientWrapper.h
  toslib/utils.h

  toslib/keys/bip39.cpp
  toslib/keys/DecryptedKey.cpp
  toslib/keys/EncryptedKey.cpp
  toslib/keys/Mnemonic.cpp
  toslib/keys/SimpleEncryption.cpp
  toslib/keys/bip39.h
  toslib/keys/DecryptedKey.h
  toslib/keys/EncryptedKey.h
  toslib/keys/Mnemonic.h
  toslib/keys/SimpleEncryption.h
)

set(TOSLIB_OFFLINE_TEST_SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/test/offline.cpp PARENT_SCOPE)
set(TOSLIB_ONLINE_TEST_SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/test/online.cpp PARENT_SCOPE)

set(USE_EMSCRIPTEN ${USE_EMSCRIPTEN} PARENT_SCOPE)

add_library(toslib STATIC ${TOSLIB_SOURCE})

target_include_directories(toslib PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>/..
  $<BUILD_INTERFACE:${OPENSSL_INCLUDE_DIR}>
)
target_link_libraries(toslib PRIVATE adnllite tl_lite_api tl-lite-utils tos_crypto lite-client-common smc-envelope emulator_static)
target_link_libraries(toslib PUBLIC tdactor tdutils tl_toslib_api)

if (TOSLIB_ENABLE_JNI AND NOT ANDROID) # jni is available by default on Android
  if (NOT JNI_FOUND)
    find_package(JNI REQUIRED)
  endif()
  message(STATUS "Found JNI: ${JNI_INCLUDE_DIRS} ${JNI_LIBRARIES}")
  target_include_directories(toslib PUBLIC ${JAVA_INCLUDE_PATH} ${JAVA_INCLUDE_PATH2})
  target_include_directories(tl_toslib_api PUBLIC ${JAVA_INCLUDE_PATH} ${JAVA_INCLUDE_PATH2})
  target_link_libraries(toslib PUBLIC ${JAVA_JVM_LIBRARY})
endif()

add_executable(toslib-cli toslib/toslib-cli.cpp)
target_link_libraries(toslib-cli toslib tdactor tdutils terminal tos_crypto git)

# ===== toslibjson =====
if (USE_EMSCRIPTEN)
  set(TOSLIBJSON_STATIC ON)
endif()

add_library(toslibjson_public_interface INTERFACE)
target_include_directories(toslibjson_public_interface INTERFACE
  $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
)

add_library(toslibjson_private_interface INTERFACE)
target_link_libraries(toslibjson_private_interface INTERFACE
  toslib tl_toslib_api_json toslibjson_public_interface
)

add_library(toslibjson_objects OBJECT
  toslib/ClientJson.cpp
  toslib/FFIEngineConsoleClient.cpp
  toslib/FFIEventLoop.cpp
  toslib/toslib_client_json.cpp
  toslib/toslib_engine_console.cpp
)
target_link_libraries(toslibjson_objects
  PRIVATE toslibjson_private_interface
  PUBLIC toslibjson_public_interface
)

if (TOSLIBJSON_STATIC)
  add_library(toslibjson STATIC $<TARGET_OBJECTS:toslibjson_objects>)
else()
  add_library(toslibjson SHARED $<TARGET_OBJECTS:toslibjson_objects>)
endif()

target_link_libraries(toslibjson
  PRIVATE toslibjson_private_interface
  PUBLIC toslibjson_public_interface
)

include(GenerateExportHeader)
generate_export_header(toslibjson EXPORT_FILE_NAME ${CMAKE_CURRENT_BINARY_DIR}/toslib/toslibjson_export.h)
if (TOSLIBJSON_STATIC)
  target_compile_definitions(toslibjson_public_interface INTERFACE TOSLIBJSON_STATIC_DEFINE)
endif()

if (NOT TOSLIBJSON_STATIC AND PORTABLE AND NOT APPLE)
  target_link_options(toslibjson PRIVATE -static-libgcc -static-libstdc++)
endif()

if (APPLE)
  set(CMAKE_MACOSX_RPATH ON)
  set(CMAKE_CXX_VISIBILITY_PRESET hidden)
  set(CMAKE_VISIBILITY_INLINES_HIDDEN ON)
endif()

if (APPLE AND PORTABLE)
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-libstdc++")
  set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -static-libstdc++")
endif()

if (APPLE)
  set_target_properties(toslibjson PROPERTIES LINK_FLAGS "-Wl,-exported_symbols_list,${CMAKE_CURRENT_SOURCE_DIR}/toslibclientjson_export_list")
endif()

add_library(ToslibJson INTERFACE)
target_link_libraries(ToslibJson INTERFACE toslibjson)

add_library(Toslib::ToslibJson ALIAS ToslibJson)

add_library(Toslib INTERFACE)
target_link_libraries(Toslib INTERFACE toslib)

add_library(Toslib::Toslib ALIAS Toslib)

install(TARGETS toslibjson_public_interface toslibjson ToslibJson EXPORT Toslib
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
  RUNTIME DESTINATION bin
  INCLUDES DESTINATION include
)

if (NOT TOS_USE_ABSEIL)
if (WIN32)
  set(WINGETOPT_TARGET wingetopt)
endif()
install(TARGETS tdnet keys crc32c tdactor adnllite tl_api tl-utils tl_lite_api tl-lite-utils tos_crypto tos_crypto_core tos_block smc-envelope ${WINGETOPT_TARGET}
  tdutils tl_toslib_api toslib lite-client-common tddb_utils emulator_static Toslib EXPORT Toslib
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
  RUNTIME DESTINATION bin
  INCLUDES DESTINATION include
)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/toslib/Client.h DESTINATION include/toslib/)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/../tl/generate/auto/tl/toslib_api.h DESTINATION include/auto/tl/)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/../tl/tl/TlObject.h DESTINATION include/tl/)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/../tdutils/td/utils/int_types.h DESTINATION include/td/utils/)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/../tdutils/td/utils/Slice-decl.h DESTINATION include/td/utils/)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/../tdutils/td/utils/Slice.h DESTINATION include/td/utils/)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/../tdutils/td/utils/common.h DESTINATION include/td/utils/)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/../tdutils/td/utils/unique_ptr.h DESTINATION include/td/utils/)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/../tdutils/td/utils/check.h DESTINATION include/td/utils/)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/../tdutils/td/utils/SharedSlice.h DESTINATION include/td/utils/)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/../tdutils/td/utils/port/platform.h DESTINATION include/td/utils/port)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/../tdutils/td/utils/config.h DESTINATION include/td/utils/)
endif()

set(TOSLIB_JSON_HEADERS
  toslib/toslib_client_json.h
  toslib/toslib_engine_console.h
)

install(FILES ${TOSLIB_JSON_HEADERS} ${CMAKE_CURRENT_BINARY_DIR}/toslib/toslibjson_export.h DESTINATION include/toslib/)

if (NOT USE_EMSCRIPTEN AND NOT TOSLIBJSON_STATIC)
  install(EXPORT Toslib
    FILE ToslibTargets.cmake
    NAMESPACE Toslib::
    DESTINATION lib/cmake/Toslib
  )

  # Add SOVERSION to shared libraries
  set_property(TARGET toslibjson PROPERTY SOVERSION ${TOS_VERSION})
endif()

include(CMakePackageConfigHelpers)
write_basic_package_version_file("ToslibConfigVersion.cmake"
  VERSION ${TOS_VERSION}
  COMPATIBILITY ExactVersion
)
install(FILES "ToslibConfig.cmake" "${CMAKE_CURRENT_BINARY_DIR}/ToslibConfigVersion.cmake"
  DESTINATION lib/cmake/Toslib
)

install(TARGETS toslib-cli RUNTIME DESTINATION bin)
