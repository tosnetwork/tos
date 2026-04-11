cmake_minimum_required(VERSION 3.16)
project(ToslibConsumerTest)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Toslib REQUIRED)

add_executable(toslibjson_consumer toslibjson_consumer.cpp)
target_link_libraries(toslibjson_consumer PRIVATE Toslib::ToslibJson)
