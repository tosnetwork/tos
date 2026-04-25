add_executable(test-persistent-treap test-persistent-treap.cpp)

target_link_libraries(test-persistent-treap PRIVATE
    tdutils
    td-test-main
)

tos_test(test-persistent-treap)

add_executable(test-lru-cache test-lru-cache.cpp)

target_link_libraries(test-lru-cache PRIVATE
    tdutils
    td-test-main
)

tos_test(test-lru-cache)
