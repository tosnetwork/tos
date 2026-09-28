add_library(metrics-core STATIC metrics-types.cpp tl-traffic-bucket.cpp)
target_include_directories(metrics-core PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>/..)
target_link_libraries(metrics-core PUBLIC tdutils tl_api tl_lite_api)

add_library(metrics STATIC prometheus-exporter.cpp metrics-collectors.cpp)
target_include_directories(metrics PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>/..)
target_link_libraries(metrics PUBLIC metrics-core tdnet toslib toshttp tdutils tdactor)

add_executable(metrics-example metrics-example.cpp)
target_include_directories(metrics-example PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>)
target_link_libraries(metrics-example PUBLIC metrics)
