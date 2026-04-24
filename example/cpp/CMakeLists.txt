cmake_minimum_required(VERSION 3.1 FATAL_ERROR)

project(TosExample VERSION 1.0 LANGUAGES CXX)

find_package(Toslib 0.5 REQUIRED)

add_executable(tosjson_example tosjson_example.cpp)
target_link_libraries(tosjson_example PRIVATE Toslib::ToslibJson)
set_property(TARGET tosjson_example PROPERTY CXX_STANDARD 11)

add_executable(toslib_example toslib_example.cpp)

target_link_libraries(toslib_example PRIVATE Toslib::Toslib)
set_property(TARGET toslib_example PROPERTY CXX_STANDARD 14)
