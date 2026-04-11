file(MAKE_DIRECTORY auto/tl)

set(TL_TOS_API
  ${CMAKE_CURRENT_SOURCE_DIR}/auto/tl/tos_api.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/auto/tl/tos_api.h
  ${CMAKE_CURRENT_SOURCE_DIR}/auto/tl/tos_api.hpp

  ${CMAKE_CURRENT_SOURCE_DIR}/auto/tl/tos_api_json.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/auto/tl/tos_api_json.h
)
set(TL_TOS_API ${TL_TOS_API} PARENT_SCOPE)

set(TL_LITE_API
  ${CMAKE_CURRENT_SOURCE_DIR}/auto/tl/lite_api.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/auto/tl/lite_api.h
  ${CMAKE_CURRENT_SOURCE_DIR}/auto/tl/lite_api.hpp
)
set(TL_LITE_API ${TL_LITE_API} PARENT_SCOPE)

set(TL_TOSLIB_API
  ${CMAKE_CURRENT_SOURCE_DIR}/auto/tl/toslib_api.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/auto/tl/toslib_api.h
  ${CMAKE_CURRENT_SOURCE_DIR}/auto/tl/toslib_api.hpp
)
set(TL_TOSLIB_API ${TL_TOSLIB_API} PARENT_SCOPE)

set(TL_TOSLIB_API_JSON
  ${CMAKE_CURRENT_SOURCE_DIR}/auto/tl/toslib_api_json.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/auto/tl/toslib_api_json.h
)
set(TL_TOSLIB_API_JSON ${TL_TOSLIB_API_JSON} PARENT_SCOPE)

set(TL_GENERATE_COMMON_SOURCE
  generate_common.cpp

  tl_json_converter.cpp
  tl_writer_cpp.cpp
  tl_writer_h.cpp
  tl_writer_hpp.cpp
  tl_writer_td.cpp
  tl_writer_jni_cpp.cpp
  tl_writer_jni_h.cpp

  tl_json_converter.h
  tl_writer_cpp.h
  tl_writer_h.h
  tl_writer_hpp.h
  tl_writer_td.h
  tl_writer_jni_cpp.h
  tl_writer_jni_h.h
)

set(TL_GENERATE_JAVA_SOURCE
  generate_java.cpp
  tl_writer_java.cpp

  tl_writer_java.h
)
add_executable(toslib_generate_java_api ${TL_GENERATE_JAVA_SOURCE})
target_link_libraries(toslib_generate_java_api PRIVATE tdtl)

if (NOT CMAKE_CROSSCOMPILING)
  foreach(tl_scheme lite_api tos_api toslib_api)
    add_custom_command(
      WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/scheme
      COMMAND
        ${CMAKE_COMMAND} -E env ASAN_OPTIONS=detect_leaks=0
        $<TARGET_FILE:tl-parser> -e "${tl_scheme}.tlo" "${tl_scheme}.tl"
      DEPENDS tl-parser "scheme/${tl_scheme}.tl"
      OUTPUT "${CMAKE_CURRENT_SOURCE_DIR}/scheme/${tl_scheme}.tlo"
    )
  endforeach()

  set(GENERATE_COMMON_CMD generate_common)
  add_executable(generate_common ${TL_GENERATE_COMMON_SOURCE})
  target_link_libraries(generate_common PRIVATE tdtl tdutils)
  add_custom_command(
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMAND ${GENERATE_COMMON_CMD}
    COMMENT "Generate common tl source files"
    DEPENDS generate_common scheme/tos_api.tlo scheme/lite_api.tlo scheme/toslib_api.tlo
    OUTPUT ${TL_TOS_API} ${TL_LITE_API} ${TL_TOSLIB_API} ${TL_TOSLIB_API_JSON}
  )
  add_custom_target(tl_generate_common DEPENDS ${TL_TOS_API} ${TL_LITE_API} ${TL_TOSLIB_API} ${TL_TOSLIB_API_JSON})
  if (TOSLIB_ENABLE_JNI)
    target_compile_definitions(generate_common PRIVATE TOSLIB_ENABLE_JNI=1)
  endif()
else()
  add_custom_target(tl_generate_common)
endif()
