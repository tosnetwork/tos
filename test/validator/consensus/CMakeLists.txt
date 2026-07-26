add_executable(test-consensus test-consensus.cpp)
target_link_libraries(test-consensus PRIVATE
    adnl
    adnltest
    dht
    overlay
    rldp
    tdactor
    tdutils
    tl_api
    tos_validator
    validator
)

add_test(
    NAME test-consensus-simplex2-loss
    COMMAND test-consensus --duration 4 --n-nodes 5 --target-rate-ms 100
            --net-ping 0.005:0.02 --net-loss 0.15 --min-finalized-blocks 5
)
add_test(
    NAME test-consensus-simplex2-restart
    COMMAND test-consensus --duration 5 --n-nodes 5 --target-rate-ms 100
            --net-ping 0.005:0.02 --gremlin-period 0.5:0.8
            --gremlin-downtime 0.1:0.2 --gremlin-times 4 --min-finalized-blocks 5
)
add_test(
    NAME test-consensus-simplex2-partition
    COMMAND test-consensus --duration 5 --n-nodes 5 --target-rate-ms 100
            --net-ping 0.005:0.02 --net-gremlin-period 0.5:0.8
            --net-gremlin-downtime 0.1:0.2 --net-gremlin-times 4 --min-finalized-blocks 5
)
add_test(
    NAME test-consensus-simplex2-malicious-observer
    COMMAND test-consensus --duration 5 --n-nodes 5 --target-rate-ms 100
            --net-ping 0.005:0.02 --malicious-observer-attack
            --min-finalized-blocks 5
)
add_test(
    NAME test-consensus-simplex2-relay-loop
    COMMAND test-consensus --duration 5 --n-nodes 5 --target-rate-ms 100
            --net-ping 0.005:0.02 --relay-loop-test
            --min-finalized-blocks 5
)
add_test(
    NAME test-consensus-simplex2-adaptive-byzantine
    COMMAND test-consensus --duration 7 --n-nodes 7 --target-rate-ms 100
            --net-ping 0.005:0.02 --adaptive-byzantine-n 2
            --adaptive-byzantine-period 0.35 --min-finalized-blocks 5
)
add_test(
    NAME test-consensus-simplex2-manager-ingress-adversarial
    COMMAND test-consensus --duration 7 --n-nodes 7 --target-rate-ms 100
            --net-ping 0.005:0.02 --malicious-observer-attack
            --relay-loop-test --adaptive-byzantine-n 2
            --adaptive-byzantine-period 0.35 --min-finalized-blocks 5
)
add_test(
    NAME test-consensus-simplex2-candidate-relay-eviction
    COMMAND test-consensus --candidate-relay-eviction-test
)
add_test(
    NAME test-consensus-simplex2-state-resolver-cache-unit
    COMMAND test-consensus --state-resolver-cache-unit-test
)
add_test(
    NAME test-consensus-simplex2-state-resolver-catch-up
    COMMAND test-consensus --duration 8 --n-nodes 5 --target-rate-ms 50
            --net-ping 0.002:0.01 --catch-up-downtime 2.5
            --min-finalized-blocks 40
)
set_tests_properties(
    test-consensus-simplex2-state-resolver-catch-up
    PROPERTIES ENVIRONMENT
        "TOS_SIMPLEX_STATE_CACHE_MAX_ENTRIES=8;TOS_SIMPLEX_FINALIZED_CACHE_MAX_ENTRIES=8"
)
add_test(
    NAME test-consensus-simplex2-query-abuse
    COMMAND test-consensus --duration 5 --n-nodes 5 --target-rate-ms 100
            --net-ping 0.005:0.02 --query-abuse-test
            --min-finalized-blocks 5
)
add_test(
    NAME test-consensus-simplex2-codec-boundary
    COMMAND test-consensus --configured-maximum-candidate-test
)
add_test(
    NAME test-consensus-simplex2-genesis-config
    COMMAND $<TARGET_FILE:create-state>
            -I ${CMAKE_SOURCE_DIR}/crypto/fift/lib
            -I ${CMAKE_SOURCE_DIR}/crypto/smartcont
            -s ${CMAKE_CURRENT_SOURCE_DIR}/simplex2-genesis-config.fif
)
