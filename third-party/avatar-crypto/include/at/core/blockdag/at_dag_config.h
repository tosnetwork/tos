#ifndef HEADER_at_tos_at_dag_config_h
#define HEADER_at_tos_at_dag_config_h

/* at_dag_config.h - BlockDAG protocol constants

   This header defines protocol-level constants for the TOS BlockDAG
   consensus mechanism. These values should match the reference
   implementation. */

#include "at/infra/at_util_base.h"

AT_PROTOTYPES_BEGIN

/* Finality parameters */

#ifndef AT_STABLE_LIMIT
#define AT_STABLE_LIMIT              (24UL)   /* Blocks for finality */
#endif
#define AT_REACHABILITY_DEPTH        (48UL)   /* 2 * STABLE_LIMIT */

/* Block limits */

#define AT_BLOCK_MAX_TIPS            (3UL)    /* Max parent blocks per block */
#define AT_BLOCK_MAX_SIZE            (1310720UL)  /* 1.25 MB */
#define AT_BLOCK_MAX_TXS             (10000UL)

/* Block hash/key sizes */

#define AT_BLOCK_HASH_SZ             (32UL)
#define AT_PUBKEY_COMPRESSED_SZ      (32UL)

/* Block versions */

#define AT_BLOCK_VERSION_NOBUNAGA    (0U)

/* Timing (milliseconds) */

#define AT_BLOCK_TIME_TARGET_MS      (1000UL) /* 1 second target */
#define AT_TIMESTAMP_FUTURE_LIMIT_MS (2000UL)  /* 2 second future tolerance */
#define AT_MILLIS_PER_SECOND         (1000UL)

/* Emission / reward parameters */
#define AT_EMISSION_SPEED_FACTOR     (20UL)
#define AT_MAXIMUM_SUPPLY            (184000000UL * 100000000UL)
#define AT_SIDE_BLOCK_REWARD_PERCENT (30UL)
#define AT_SIDE_BLOCK_REWARD_MAX_BLOCKS (3UL)
#define AT_SIDE_BLOCK_REWARD_MIN_PERCENT (5UL)

/* Dev fee thresholds (percentages applied to block reward only) */
#define AT_DEV_FEE_HEIGHT_0          (0UL)
#define AT_DEV_FEE_PERCENT_0         (10UL)
#define AT_DEV_FEE_HEIGHT_1          (15768000UL)
#define AT_DEV_FEE_PERCENT_1         (5UL)

/* Difficulty parameters */

#define AT_DIFFICULTY_MIN_MAINNET    (100000UL)  /* 100 KH/s minimum */
#define AT_DIFFICULTY_MIN_TESTNET    (10000UL)   /* 10 KH/s minimum */
#define AT_DIFFICULTY_MIN_DEVNET     (1000UL)    /* 1 KH/s minimum */

/* Kalman filter parameters */

#define AT_KALMAN_SHIFT              (20UL)               /* 2^20 scaling factor */
#define AT_KALMAN_LEFT_SHIFT         (1UL << AT_KALMAN_SHIFT)
/* Process noise = (2^20 * 20) / 1000 = 20971 */
#define AT_KALMAN_PROCESS_NOISE      ((AT_KALMAN_LEFT_SHIFT * AT_KALMAN_SHIFT) / AT_MILLIS_PER_SECOND)
#define AT_KALMAN_INITIAL_P          (AT_KALMAN_LEFT_SHIFT)

/* DAG limits */

#define AT_TIPS_MAX_COUNT            (64UL)   /* Max concurrent tips */
#define AT_MAX_REACHABILITY_SET      (256UL)  /* Max ancestors to track */
#define AT_MAX_FULL_ORDER_SIZE       (1024UL) /* Max blocks in full order */

/* Pruning parameters */

#define AT_PRUNE_SAFETY_LIMIT        (AT_STABLE_LIMIT * 10UL)  /* 240 blocks */

/* Reorg limits */

#define AT_MAX_ORPHANED_TXS          (10000UL) /* Max orphaned TXs during reorg */

/* Error codes */

#define AT_DAG_SUCCESS               (0)
#define AT_DAG_ERR_NO_TIPS           (-1)
#define AT_DAG_ERR_NOT_FOUND         (-2)
#define AT_DAG_ERR_CORRUPT           (-3)
#define AT_DAG_ERR_REACHABLE         (-4)
#define AT_DAG_ERR_DUPLICATE_TIP     (-5)
#define AT_DAG_ERR_TIP_NOT_FOUND     (-6)
#define AT_DAG_ERR_INVALID_HEIGHT    (-7)
#define AT_DAG_ERR_INVALID_TIMESTAMP (-8)
#define AT_DAG_ERR_INVALID_DIFF      (-9)
#define AT_DAG_ERR_QUEUE_FULL        (-10)
#define AT_DAG_ERR_INVAL             (-11)
#define AT_DAG_ERR_OVERFLOW          (-12)
#define AT_DAG_ERR_FULL              (-13)

/* Get stable limit based on block version */

static inline ulong
at_dag_get_stable_limit( uint block_version ) {
  (void)block_version;  /* Currently all versions use same limit */
  return AT_STABLE_LIMIT;
}

/* Reachability depth = 2 * stable_limit */

static inline ulong
at_dag_get_reachability_depth( uint block_version ) {
  return at_dag_get_stable_limit( block_version ) * 2UL;
}

/* Get side block reward percentage based on side block count */
static inline ulong
at_side_block_reward_percentage( ulong side_blocks ) {
  ulong pct = AT_SIDE_BLOCK_REWARD_PERCENT;
  if( side_blocks > 0 ) {
    if( side_blocks < AT_SIDE_BLOCK_REWARD_MAX_BLOCKS ) {
      pct = AT_SIDE_BLOCK_REWARD_PERCENT / (side_blocks * 2UL);
    } else {
      pct = AT_SIDE_BLOCK_REWARD_MIN_PERCENT;
    }
  }
  return pct;
}

/* Get dev fee percentage based on block height */
static inline ulong
at_block_dev_fee( ulong height ) {
  ulong pct = AT_DEV_FEE_PERCENT_0;
  if( height >= AT_DEV_FEE_HEIGHT_1 ) pct = AT_DEV_FEE_PERCENT_1;
  return pct;
}

AT_PROTOTYPES_END

#endif /* HEADER_at_tos_at_dag_config_h */
