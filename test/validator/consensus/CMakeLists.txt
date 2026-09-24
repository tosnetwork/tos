add_executable(test-consensus test-consensus.cpp)
target_link_libraries(test-consensus PRIVATE
    adnl
    adnltest
    dht
    overlay
    tdactor
    tdutils
    tl_api
    tos_validator
    validator
)

# The live sign->verify round through PeerValidator::check_signature.
add_executable(test-consensus-verify test-consensus-verify.cpp)
set_target_properties(test-consensus-verify PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
target_link_libraries(test-consensus-verify PRIVATE
    validator
    tos_validator
    adnl
    overlay
    dht
    tl_api
    tl-utils
    tos_crypto
    tos_pq_consensus_signer
    tos_pq_consensus
    tos_mldsa44
    tdactor
    tdutils
)
add_test(NAME consensus-verify COMMAND test-consensus-verify)

# The structural and cryptographic guards on the live Simplex entrypoints, under
# post-quantum keys. It links the production sources through `validator`; nothing here
# re-implements quorum arithmetic or signature checking.
add_executable(test-certificate-conformance test-certificate-conformance.cpp)
set_target_properties(test-certificate-conformance PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
target_link_libraries(test-certificate-conformance PRIVATE
    validator
    tos_validator
    tos_block
    adnl
    overlay
    dht
    tl_api
    tl-utils
    tos_crypto
    tos_pq_consensus_signer
    tos_pq_consensus
    tos_mldsa44
    tdactor
    tdutils
)
add_test(NAME certificate-conformance COMMAND test-certificate-conformance)

# The same binary emits one transcript per signing domain. This rebuilds each preimage from
# the TL constructor schemas in Python and requires an exact match, so the C++ serializer
# cannot agree with itself about a change to what a validator signs.
find_package(Python3 COMPONENTS Interpreter)
if(Python3_Interpreter_FOUND)
    add_test(NAME simplex-preimages
             COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/check-simplex-preimages.py
                     $<TARGET_FILE:test-certificate-conformance>)
endif()

# One validator node running the production Pool, CandidateResolver, StateResolver and Db,
# fed real quorum certificates in a controlled order: NotarCert(P) held in its database write
# while SkipCert(P.slot) and NotarCert(C) are installed and a leader window opens on C.
add_executable(test-merkle-prospective-notar test-merkle-prospective-notar.cpp)
target_link_libraries(test-merkle-prospective-notar PRIVATE
    validator
    tos_validator
    tos_block
    adnl
    overlay
    dht
    tl_api
    tl-utils
    tos_crypto
    tos_pq_consensus_signer
    tos_pq_consensus
    tos_mldsa44
    tdactor
    tdutils
)

# A controlled transient ResolveState failure inside the production Consensus actor.
add_executable(test-notarize-after-transient-resolve test-notarize-after-transient-resolve.cpp)
target_link_libraries(test-notarize-after-transient-resolve PRIVATE
    validator
    tos_validator
    tos_block
    adnl
    overlay
    dht
    tl_api
    tl-utils
    tos_crypto
    tos_pq_consensus_signer
    tos_pq_consensus
    tos_mldsa44
    tdactor
    tdutils
)
foreach(mode control genesis-notready genesis-timeout ancestor-notready permanent cancelled skip-before-recovery
             conflict-during-retry conflicting-cert-during-retry exhausted-notready)
    add_test(NAME c05-notarize-${mode} COMMAND test-notarize-after-transient-resolve ${mode})
endforeach()

add_executable(test-validator-manager-resource-policy test-validator-manager-resource-policy.cpp)
target_link_libraries(test-validator-manager-resource-policy PRIVATE
    adnl
    adnltest
    dht
    overlay
    tdactor
    tdutils
    tl_api
    tos_validator
    validator
)

add_executable(test-liteserver-admission test-liteserver-admission.cpp)
target_link_libraries(test-liteserver-admission PRIVATE
    td-test-main
    tdutils
    tl_api
)
tos_test(test-liteserver-admission)

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
    NAME test-consensus-simplex2-state-resolver-inflight-admission-unit
    COMMAND test-consensus --state-resolver-inflight-admission-unit-test
)
add_test(
    NAME test-consensus-simplex2-merkle-exact-parent-height-control
    COMMAND test-consensus --merkle-exact-parent-height-control-test
)
add_test(
    NAME test-consensus-simplex2-candidate-resolver-retention-unit
    COMMAND test-consensus --candidate-resolver-retention-unit-test
)
add_test(
    NAME test-consensus-simplex2-candidate-resolver-interleaving-unit
    COMMAND test-consensus --candidate-resolver-interleaving-unit-test
)
add_test(
    NAME test-consensus-simplex2-db-finalized-slot-dedup-unit
    COMMAND test-consensus --simplex-db-finalized-slot-dedup-unit-test
)
add_test(
    NAME test-consensus-validator-manager-resource-policy-unit
    COMMAND test-consensus --validator-manager-resource-policy-unit-test
)
add_test(
    NAME test-validator-manager-resource-policy-actor
    COMMAND test-validator-manager-resource-policy
)
add_test(
    NAME test-consensus-simplex2-pq-state-resolver-catch-up
    COMMAND test-consensus --duration 8 --n-nodes 5 --target-rate-ms 50
            --net-ping 0.002:0.01 --catch-up-downtime 2.5
            --min-finalized-blocks 40 --pq-finality-e2e-test
)
set_tests_properties(
    test-consensus-simplex2-pq-state-resolver-catch-up
    PROPERTIES ENVIRONMENT
        "TOS_SIMPLEX_STATE_CACHE_MAX_ENTRIES=8;TOS_SIMPLEX_FINALIZED_CACHE_MAX_ENTRIES=8;TOS_SIMPLEX_CANDIDATE_RETENTION_SLOTS=8"
)
# The post-quantum round end to end. It observes a verified FinalCert becoming the #13
# carrier and at least three consecutive accepted blocks, independently verifies every
# accepted proof under its trusted context, and compares one proof's carried signatures
# byte-for-byte with its signer journal, the FinalCert, a database round trip and a
# BlockProof load.
add_test(
    NAME test-consensus-simplex2-pq-finality-e2e-single
    COMMAND test-consensus --duration 40 --n-nodes 1 --target-rate-ms 100
            --net-ping 0:0 --pq-finality-e2e-test
)
add_test(
    NAME test-consensus-simplex2-pq-finality-e2e-multi
    COMMAND test-consensus --duration 40 --n-nodes 4 --target-rate-ms 100
            --net-ping 0.005:0.02 --pq-finality-e2e-test
)
# The structural scales the end-to-end gate asks for, at the two this harness can carry. Measured on one
# developer machine: 21 nodes in 0.4s, 100 in 2.5s. The measurements and the boundary above
# them are recorded in the plan document; the launch measurement set runs on real hosts.
add_test(
    NAME test-consensus-simplex2-pq-finality-e2e-21
    COMMAND test-consensus --duration 120 --n-nodes 21 --target-rate-ms 100
            --net-ping 0.005:0.02 --pq-finality-e2e-test
)
add_test(
    NAME test-consensus-simplex2-pq-finality-e2e-100
    COMMAND test-consensus --duration 300 --n-nodes 100 --target-rate-ms 100
            --net-ping 0.005:0.02 --pq-finality-e2e-test
)
# The same gate with the finalization concurrency limit set to one, which is what lets the
# retry probe build the pressure it needs: a finalization refused before its attempt begins,
# and one that fails inside it. Both have to come back rather than disappear -- a certificate
# dropped with nothing left to ask for it again becomes a stuck chain once blocks are accepted.
add_test(
    NAME test-consensus-simplex2-pq-finality-retry
    COMMAND test-consensus --duration 40 --n-nodes 4 --target-rate-ms 100
            --net-ping 0.005:0.02 --pq-finality-e2e-test --finalization-retry-probe
)
set_tests_properties(
    test-consensus-simplex2-pq-finality-retry
    PROPERTIES ENVIRONMENT "TOS_SIMPLEX_FINALIZED_INFLIGHT_MAX=1"
)
# The property the retry exists for, which a count of retries does not show: a transient
# condition that outlasts the first several attempts still ends with the certificate every
# node agreed on being finalized, and nothing re-announces it -- the event that carried it
# was consumed by the first attempt.
#
# Twelve injected failures, against the four the first version of this code gave up at. An
# implementation that gives up loses the certificate here and never finalizes it at
# all, which is what the gate reports. The condition is injected because a build that stops
# after one slot has no natural pressure that can be turned on and then off.
add_test(
    NAME test-consensus-simplex2-pq-finality-transient-recovery
    COMMAND test-consensus --duration 40 --n-nodes 4 --target-rate-ms 100
            --net-ping 0.005:0.02 --pq-finality-e2e-test
)
set_tests_properties(
    test-consensus-simplex2-pq-finality-transient-recovery
    PROPERTIES ENVIRONMENT "TOS_SIMPLEX_INJECT_TRANSIENT_FINALIZATION_FAILURES=12"
)
# Keeping every certificate and retrying it for as long as the group lives is what stops one
# being lost. It is also how a failure that does not clear turns into unbounded work: the
# pool advances the round the moment a quorum finalizes a slot, so every later slot adds
# another certificate to hold and another retry, while the one at the front never completes.
#
# Nothing is dropped to bound that. Production stops instead. With the hold set to one and
# failures injected past it, the group has to report the backlog, produce no candidate while
# it is over, and then -- once the injected failures run out -- report that it cleared and
# accept at least one block. This scenario deliberately throttles finalization, so it does
# not inherit the general gate's three-consecutive-block requirement; its lower progress
# count is valid only together with the explicit over-limit, no-production, and recovery
# assertions above.
add_test(
    NAME test-consensus-simplex2-pq-finality-backpressure
    COMMAND test-consensus --duration 80 --n-nodes 4 --target-rate-ms 100
            --net-ping 0.005:0.02 --pq-finality-e2e-test
            --finalization-backpressure-test
)
set_tests_properties(
    test-consensus-simplex2-pq-finality-backpressure
    PROPERTIES ENVIRONMENT
        "TOS_SIMPLEX_INJECT_TRANSIENT_FINALIZATION_FAILURES=12;TOS_SIMPLEX_PENDING_FINALIZATIONS_MAX=1"
)
# The other half of the same policy: a failure retrying cannot mend. Nothing before the
# normal test traffic does not produce one, so it is injected -- and without that, the branch
# that handles it would be a guard no input can reach, which is the same as not having
# written it. The certificate is kept, because it is still evidence a quorum agreed; it is
# not retried, because that is what the classification says is pointless here; and one of
# them stops the group on its own, whatever the backlog limit says, because a chain that
# cannot pass this slot gains nothing from producing the next.
add_test(
    NAME test-consensus-simplex2-pq-finality-permanent
    COMMAND test-consensus --duration 40 --n-nodes 4 --target-rate-ms 100
            --net-ping 0.005:0.02 --permanent-finalization-test
)
set_tests_properties(
    test-consensus-simplex2-pq-finality-permanent
    PROPERTIES ENVIRONMENT "TOS_SIMPLEX_INJECT_PERMANENT_FINALIZATION_FAILURE=1"
)
# The same gate, with the adversarial scenarios turned on. Their attack machinery was never
# the part that needed the carrier -- only their `--min-finalized-blocks` assertion was -- so running
# them against the post-quantum gate restores the end-to-end half of the checklist: that
# traffic from outside the validator set does not become authority, that certificate gossip
# deduplicates, that an adaptive Byzantine membership does not stop the round, and that an
# agreed certificate is still reached under packet loss, node churn and partition. Each
# scenario has to inject its adversity before the round it is credited with.
#
# What these do NOT establish, despite the temptation to claim it: that a *valid* signature
# attributed to the wrong signer index is refused. The malicious observer sends a
# classical-length signature from outside the set, so a rejection here could be for the
# length rather than for the attribution. That property is proven where the inputs can be
# built exactly -- certificate-conformance, with real post-quantum signatures, covers a
# vote signed by one validator presented as another, an out-of-range index and a repeated
# signer; and consensus-verify covers a genuine transport-key signature carrying no
# consensus authority.
add_test(
    NAME test-consensus-simplex2-pq-malicious-observer
    COMMAND test-consensus --duration 40 --n-nodes 5 --target-rate-ms 100
            --net-ping 0.005:0.02 --malicious-observer-attack --pq-finality-e2e-test
)
add_test(
    NAME test-consensus-simplex2-pq-relay-loop
    COMMAND test-consensus --duration 40 --n-nodes 5 --target-rate-ms 100
            --net-ping 0.005:0.02 --relay-loop-test --pq-finality-e2e-test
)
add_test(
    NAME test-consensus-simplex2-pq-adaptive-byzantine
    COMMAND test-consensus --duration 40 --n-nodes 7 --target-rate-ms 100
            --net-ping 0.005:0.02 --adaptive-byzantine-n 2
            --adaptive-byzantine-period 0.35 --pq-finality-e2e-test
)
add_test(
    NAME test-consensus-simplex2-pq-manager-ingress-adversarial
    COMMAND test-consensus --duration 40 --n-nodes 7 --target-rate-ms 100
            --net-ping 0.005:0.02 --malicious-observer-attack --relay-loop-test
            --adaptive-byzantine-n 2 --adaptive-byzantine-period 0.35 --pq-finality-e2e-test
)
# One validator passes the others' signed votes on as its own, byte for byte, over its own
# correctly authenticated transport. Nothing is forged and a vote carries no signer field, so
# the only thing that could make a relayed vote count as the relayer's is the transport it
# arrived over. This is the end-to-end form of the property the certificate conformance test
# proves at unit level: attribution follows the signature, never the transport.
add_test(
    NAME test-consensus-simplex2-pq-byzantine-relay
    COMMAND test-consensus --duration 40 --n-nodes 7 --target-rate-ms 100
            --net-ping 0.005:0.02 --byzantine-relay-node 3 --pq-finality-e2e-test
)
add_test(
    NAME test-consensus-simplex2-pq-query-abuse
    COMMAND test-consensus --duration 40 --n-nodes 5 --target-rate-ms 100
            --net-ping 0.005:0.02 --query-abuse-test --pq-finality-e2e-test
)
add_test(
    NAME test-consensus-simplex2-pq-loss
    COMMAND test-consensus --duration 40 --n-nodes 5 --target-rate-ms 100
            --net-ping 0.005:0.02 --net-loss 0.15 --pq-finality-e2e-test
)
add_test(
    NAME test-consensus-simplex2-pq-restart
    COMMAND test-consensus --duration 40 --n-nodes 5 --target-rate-ms 100
            --net-ping 0.005:0.02 --gremlin-period 0.5:0.8
            --gremlin-downtime 0.1:0.2 --gremlin-times 4 --pq-finality-e2e-test
)
add_test(
    NAME test-consensus-simplex2-pq-partition
    COMMAND test-consensus --duration 40 --n-nodes 5 --target-rate-ms 100
            --net-ping 0.005:0.02 --net-gremlin-period 0.5:0.8
            --net-gremlin-downtime 0.1:0.2 --net-gremlin-times 4 --pq-finality-e2e-test
)

# Two of the no-fallback invariants are properties of the source that no run can observe:
# a legacy carrier built and thrown away, and a keyring signature produced and discarded.
# They are checked where they exist, in the code.
if(Python3_Interpreter_FOUND)
    # The exact-ancestor resolver under a controlled certificate order. The pre-fix
    # resolver fails the `green` expectation with the N/N-1 Merkle abort; see
    # doc/pq-native/N6-MERKLE-REPRO-20260923.md for the recorded old-RED runs.
    set(MERKLE_PROSPECTIVE_NOTAR_CHECK ${CMAKE_CURRENT_SOURCE_DIR}/check-merkle-prospective-notar.py)
    add_test(NAME test-consensus-simplex2-merkle-prospective-notar-exact-ancestor
             COMMAND ${Python3_EXECUTABLE} ${MERKLE_PROSPECTIVE_NOTAR_CHECK}
                     $<TARGET_FILE:test-merkle-prospective-notar> green --n 5 --n 23)
    add_test(NAME test-consensus-simplex2-merkle-prospective-notar-bounded-refusal
             COMMAND ${Python3_EXECUTABLE} ${MERKLE_PROSPECTIVE_NOTAR_CHECK}
                     $<TARGET_FILE:test-merkle-prospective-notar> bounded --n 5)
    set_tests_properties(test-consensus-simplex2-merkle-prospective-notar-bounded-refusal
                         PROPERTIES ENVIRONMENT "TOS_SIMPLEX_CANDIDATE_RESOLVE_MAX_ATTEMPTS=2")
    add_test(NAME test-consensus-simplex2-merkle-prospective-notar-control
             COMMAND ${Python3_EXECUTABLE} ${MERKLE_PROSPECTIVE_NOTAR_CHECK}
                     $<TARGET_FILE:test-merkle-prospective-notar> control --n 5 --n 23)
    # NotarCert(P) only on a peer node without a Pool; the node under test resolves C from
    # the real Consensus::start_generation after Pool opens its leader window on C.
    add_test(NAME test-consensus-simplex2-merkle-peer-notar-leader-path
             COMMAND ${Python3_EXECUTABLE} ${MERKLE_PROSPECTIVE_NOTAR_CHECK}
                     $<TARGET_FILE:test-merkle-prospective-notar> peer-green --n 5 --n 23)
    add_test(NAME test-consensus-simplex2-merkle-prospective-notar-gate-control
             COMMAND ${Python3_EXECUTABLE} ${MERKLE_PROSPECTIVE_NOTAR_CHECK}
                     $<TARGET_FILE:test-merkle-prospective-notar> gate --n 5)
    add_test(NAME simplex-exact-ancestor-source-guard
             COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/scripts/check-simplex-exact-ancestor-resolution.py ${CMAKE_SOURCE_DIR})
    set_tests_properties(simplex-exact-ancestor-source-guard PROPERTIES LABELS "source-guard")
    add_test(NAME consensus-no-fallback
             COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/check-no-fallback.py)
    set_tests_properties(consensus-no-fallback PROPERTIES LABELS "source-guard")
endif()

# The two-phase own-vote journal: signed records replay byte for byte, an
# intent-only record is signed once, and a record this node cannot verify as its own
# stops the group instead of producing a second signature.
add_test(
    NAME test-consensus-simplex2-vote-journal
    COMMAND test-consensus --duration 30 --n-nodes 1 --target-rate-ms 50
            --net-ping 0:0 --vote-journal-test
)
add_test(
    NAME test-consensus-simplex2-pq-empty-chain-restart
    COMMAND test-consensus --duration 110 --n-nodes 1 --target-rate-ms 1
            --net-ping 0:0 --empty-chain-restart-test --min-finalized-blocks 1
            --pq-finality-e2e-test
)
# SR1: a restarted session may start at the latest accepted tip while its
# persisted candidate chain reaches back to genesis. A temporarily unavailable
# finalized anchor must not make the resolver replay an old update on that tip.
add_test(
    NAME test-consensus-simplex2-pq-restart-transient-anchor
    COMMAND test-consensus --duration 110 --n-nodes 1 --target-rate-ms 1
            --net-ping 0:0 --empty-chain-restart-test --min-finalized-blocks 1
            --pq-finality-e2e-test
)
set_tests_properties(test-consensus-simplex2-pq-restart-transient-anchor PROPERTIES
    ENVIRONMENT "TOS_TEST_RESTART_FROM_LAST_ACCEPTED_BLOCK=1;TOS_TEST_ANCHOR_TRANSIENT_FAILURES=2")
add_test(
    NAME test-consensus-simplex2-pq-restart-transient-anchor-zerostate-control
    COMMAND test-consensus --duration 110 --n-nodes 1 --target-rate-ms 1
            --net-ping 0:0 --empty-chain-restart-test --min-finalized-blocks 1
            --pq-finality-e2e-test
)
set_tests_properties(test-consensus-simplex2-pq-restart-transient-anchor-zerostate-control PROPERTIES
    ENVIRONMENT "TOS_TEST_ANCHOR_TRANSIENT_FAILURES=2")
add_test(
    NAME test-consensus-simplex2-pq-restart-transient-origin
    COMMAND test-consensus --duration 110 --n-nodes 1 --target-rate-ms 1
            --net-ping 0:0 --empty-chain-restart-test --min-finalized-blocks 1
            --pq-finality-e2e-test
)
set_tests_properties(test-consensus-simplex2-pq-restart-transient-origin PROPERTIES
    ENVIRONMENT "TOS_TEST_RESTART_FROM_LAST_ACCEPTED_BLOCK=1;TOS_TEST_ANCHOR_TRANSIENT_FAILURES=2;TOS_TEST_ORIGIN_TRANSIENT_FAILURES=2")
add_test(
    NAME test-consensus-simplex2-pq-restart-permanent-origin
    COMMAND test-consensus --duration 110 --n-nodes 1 --target-rate-ms 1
            --net-ping 0:0 --empty-chain-restart-test --min-finalized-blocks 1
            --pq-finality-e2e-test
)
set_tests_properties(test-consensus-simplex2-pq-restart-permanent-origin PROPERTIES
    ENVIRONMENT "TOS_TEST_RESTART_FROM_LAST_ACCEPTED_BLOCK=1;TOS_TEST_ORIGIN_PERMANENTLY_UNAVAILABLE=1")
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
            -I ${CMAKE_BINARY_DIR}/crypto/smartcont
            -I ${CMAKE_SOURCE_DIR}/crypto/smartcont
            -s ${CMAKE_CURRENT_SOURCE_DIR}/simplex2-genesis-config.fif
)

# These legacy full-finalization scenarios remain only as historical regressions. Each has
# an enabled post-quantum counterpart above, including accepted-chain catch-up and the long
# empty-chain restart.
set_tests_properties(
    test-consensus-simplex2-loss
    test-consensus-simplex2-restart
    test-consensus-simplex2-partition
    test-consensus-simplex2-malicious-observer
    test-consensus-simplex2-relay-loop
    test-consensus-simplex2-adaptive-byzantine
    test-consensus-simplex2-manager-ingress-adversarial
    test-consensus-simplex2-query-abuse
    PROPERTIES DISABLED TRUE
)
