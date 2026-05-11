add_executable(type_generator main.cpp)

target_link_libraries(type_generator
  avata_jvm_finder
  avata_util
  avata_system
  ${ZLIB_LIBRARIES}
  ${PLATFORM_LIBS}
)
