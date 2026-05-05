add_executable(type_generator main.cpp)

target_link_libraries(type_generator
  avata_jvm_finder
  avata_system
  avata_util
  ${ZLIB_LIBRARIES}
  ${PLATFORM_LIBS}
)
