#ifndef HEADER_at_blockdag_at_difficulty_h
#define HEADER_at_blockdag_at_difficulty_h

/* at_difficulty.h - Difficulty adjustment for TOS BlockDAG

   This header defines the Kalman filter-based difficulty adjustment
   algorithm (V2) used in TOS. The algorithm estimates network hashrate
   and adjusts difficulty to maintain target block time.

   Key features:
   - Kalman filter for smooth hashrate estimation
   - Adaptive measurement noise based on observed hashrate
   - Minimum difficulty enforcement per network type
   - Covariance tracking for filter state */

#include "at/infra/at_util_base.h"
#include "at/core/blockdag/at_dag_config.h"

AT_PROTOTYPES_BEGIN

/* Type definitions */

typedef ulong at_difficulty_t;
typedef ulong at_cumulative_difficulty_t;

/* Network type for minimum difficulty selection
   Note: May also be defined in at_p2p_msg.h - use guard to avoid redefinition */

#ifndef AT_NETWORK_TYPE_DEFINED
#define AT_NETWORK_TYPE_DEFINED
typedef enum {
  AT_NETWORK_MAINNET  = 0,
  AT_NETWORK_TESTNET  = 1,
  AT_NETWORK_STAGENET = 2,
  AT_NETWORK_DEVNET   = 3,
} at_network_t;
typedef at_network_t at_network_type_t;
#endif

/* Difficulty state for Kalman filter */

typedef struct {
  at_difficulty_t difficulty;   /* Current difficulty */
  ulong           covariance;   /* Kalman filter covariance (P) */
} at_difficulty_state_t;

/* Get minimum difficulty for a network type */

static inline at_difficulty_t
at_difficulty_minimum( at_network_type_t network ) {
  switch( network ) {
    case AT_NETWORK_MAINNET: return AT_DIFFICULTY_MIN_MAINNET;
    case AT_NETWORK_TESTNET: return AT_DIFFICULTY_MIN_TESTNET;
    case AT_NETWORK_DEVNET:  return AT_DIFFICULTY_MIN_DEVNET;
    case AT_NETWORK_STAGENET: return AT_DIFFICULTY_MIN_TESTNET;
    default:                 return AT_DIFFICULTY_MIN_DEVNET;
  }
}

/* Calculate difficulty V2 (Kalman filter)

   This function implements the difficulty adjustment algorithm matching
   the TOS Rust implementation in core/difficulty/v2.rs.

   Args:
     solve_time:          Time between parent and current block (ms)
     previous_difficulty: Parent block's difficulty
     p:                   Parent block's Kalman covariance
     minimum_difficulty:  Network minimum difficulty
     block_time_target:   Target block time (ms)
     out_difficulty:      Output: new difficulty
     out_covariance:      Output: new covariance

   Returns:
     AT_DAG_SUCCESS on success, error code otherwise.

   Note: When difficulty is clamped to minimum, covariance is reset
   to AT_KALMAN_INITIAL_P to allow faster recovery. */

int
at_difficulty_calculate_v2( ulong   solve_time,
                            ulong   previous_difficulty,
                            ulong   p,
                            ulong   minimum_difficulty,
                            ulong   block_time_target,
                            ulong * out_difficulty,
                            ulong * out_covariance );

/* Forward declaration for provider */
struct at_dag_provider;
typedef struct at_dag_provider at_dag_provider_t;

/* Calculate cumulative difficulty for a new block

   Cumulative difficulty is used for fork choice - the chain with
   highest cumulative difficulty is preferred.

   TOS Rust algorithm (find_tip_work_score):
   1. Find common base block among all tips
   2. BFS from each tip backward to base, collecting unique block
      difficulties (deduplicating shared ancestors)
   3. Sum: block_difficulty + all collected + base.cumulative_difficulty

   For single-tip blocks this reduces to parent.cumulative + block_diff.

   Args:
     provider:         DAG storage provider
     tips:             Parent block hashes
     tips_cnt:         Number of parent blocks
     block_difficulty: This block's difficulty

   Returns:
     Cumulative difficulty for the new block. */

at_cumulative_difficulty_t
at_difficulty_cumulative( at_dag_provider_t const * provider,
                          uchar const             (* tips)[AT_BLOCK_HASH_SZ],
                          ulong                     tips_cnt,
                          at_difficulty_t           block_difficulty );

/* Calculate cumulative difficulty using work score

   Work score sums the difficulties of ALL blocks reachable from the
   tip down to a base block. This is more accurate than simple
   cumulative difficulty for complex DAG scenarios.

   Args:
     provider:         DAG storage provider
     tip_hash:         Tip block hash
     base_hash:        Base block hash (stable point)

   Returns:
     Total work score from tip to base. */

at_cumulative_difficulty_t
at_difficulty_work_score( at_dag_provider_t const * provider,
                          uchar const             * tip_hash,
                          uchar const             * base_hash );

/* Verify difficulty is valid for a block

   Checks that the block's difficulty matches what would be calculated
   from its parent using the Kalman filter algorithm.

   Args:
     solve_time:          Time between parent and current block (ms)
     previous_difficulty: Parent block's difficulty
     previous_covariance: Parent block's Kalman covariance
     claimed_difficulty:  Block's claimed difficulty
     minimum_difficulty:  Network minimum difficulty
     block_time_target:   Target block time (ms)
     tolerance_pct:       Allowed deviation percentage (0-100)

   Returns:
     1 if difficulty is valid, 0 otherwise. */

int
at_difficulty_verify( ulong solve_time,
                      ulong previous_difficulty,
                      ulong previous_covariance,
                      ulong claimed_difficulty,
                      ulong minimum_difficulty,
                      ulong block_time_target,
                      ulong tolerance_pct );

AT_PROTOTYPES_END

#endif /* HEADER_at_blockdag_at_difficulty_h */
