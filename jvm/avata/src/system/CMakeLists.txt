
if (MSVC)
  #todo: support mingw compiler
  add_library(avata_system windows.cpp windows/crash.cpp)
else()
  add_library(avata_system posix.cpp posix/crash.cpp)
endif()
