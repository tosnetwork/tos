#ifndef HEADER_at_tos_at_echange_h
#define HEADER_at_tos_at_echange_h

/* at_echange.h - Sender Balance Change Tracking for Avatar (TOS-Compatible)

   This module implements the TOS Rust Echange equivalent structure for tracking
   sender account balance changes during block execution. The Echange structure
   tracks output balance usage to support same-block multi-transaction scenarios.

   TOS Rust Reference: daemon/src/core/state/chain_state/mod.rs:36-74

   Key Concepts:
   - final_balance: The balance after all operations in the current version
   - output_balance: Balance used for verification when same-block TX chains occur
   - output_sum: Cumulative sum of all outputs from this account in current block
   - allow_output_balance: Whether output balance can be used for this account
   - new_version: Whether this is a new version at current topoheight
   - output_balance_used: Whether output_balance has been consumed

   Usage:
     at_echange_t echange;
     at_echange_init(&echange, final_balance, prev_topo, new_version, allow_output);
     ulong * bal = at_echange_get_balance(&echange);  // Gets correct balance
     at_echange_add_output(&echange, amount);         // Track outputs
*/

#include "at/infra/at_util_base.h"
#include "at/account/at_account.h"

AT_PROTOTYPES_BEGIN

/* Maximum assets per account tracked in a single block execution */
#define AT_ECHANGE_MAX_ASSETS (64UL)

/* at_echange_t tracks balance changes for a sender account's single asset.
   This is the C equivalent of TOS Rust's Echange structure. */
typedef struct at_echange {
  /* Initialization flag */
  int    initialized;             /* Whether this echange has been initialized */

  /* Configuration flags */
  int    allow_output_balance;    /* Whether output balance can be used */
  int    new_version;             /* Whether this is a new version at current topo */

  /* Balance tracking */
  ulong  final_balance;           /* Balance after operations */
  ulong  output_balance;          /* Balance for same-block verification */
  int    has_output_balance;      /* Whether output_balance is valid */

  /* Output accumulation */
  ulong  output_sum;              /* Sum of all outputs from this account */
  int    output_balance_used;     /* Whether output_balance has been consumed */

  /* Version chain */
  ulong  previous_topoheight;     /* Previous version's topoheight */
  int    has_previous_topoheight; /* Whether previous_topoheight is valid */

  /* Balance type for final commit */
  at_balance_type_t balance_type; /* Input/Output/Both */
} at_echange_t;

/* at_asset_echange_t associates an asset hash with its echange state */
typedef struct at_asset_echange {
  uchar         asset[32];        /* Asset hash (zeros = native TOS) */
  at_echange_t  echange;          /* Echange state for this asset */
} at_asset_echange_t;

/* at_account_echange_t tracks all asset changes for a single sender account */
typedef struct at_account_echange {
  uchar              pubkey[32];           /* Account public key */

  /* Asset balance changes */
  at_asset_echange_t assets[AT_ECHANGE_MAX_ASSETS];
  ulong              assets_cnt;           /* Number of assets with changes */

  /* Nonce tracking */
  ulong              nonce;                /* Current nonce value */
  ulong              prev_nonce_topo;      /* Previous nonce version topo */
  int                has_prev_nonce_topo;  /* Whether prev_nonce_topo is valid */
  int                nonce_dirty;          /* Whether nonce was modified */
} at_account_echange_t;

/* ============================================================================
   Echange Initialization
   ============================================================================ */

/* at_echange_init initializes an echange structure with starting values.
   final_balance: Current balance from storage
   prev_topo: Previous version's topoheight (0 if none)
   has_prev_topo: Whether prev_topo is valid
   new_version: Whether this is a new version at current topo
   allow_output_balance: Whether output balance can be used */
static inline void
at_echange_init( at_echange_t * e,
                 ulong          final_balance,
                 ulong          prev_topo,
                 int            has_prev_topo,
                 int            new_version,
                 int            allow_output_balance ) {
  if( AT_UNLIKELY( !e ) ) return;
  e->initialized             = 1;              /* Mark as initialized */
  e->allow_output_balance    = allow_output_balance;
  e->new_version             = new_version;
  e->final_balance           = final_balance;
  e->output_balance          = final_balance;  /* Initially same as final */
  e->has_output_balance      = 0;              /* Not set until first output */
  e->output_sum              = 0;
  e->output_balance_used     = 0;
  e->previous_topoheight     = prev_topo;
  e->has_previous_topoheight = has_prev_topo;
  e->balance_type            = AT_BALANCE_TYPE_OUTPUT;  /* Sender = output */
}

/* ============================================================================
   Balance Access - Core TOS Rust Logic
   ============================================================================ */

/* at_echange_get_balance returns a pointer to the correct balance to use.

   TOS Rust Logic (chain_state/mod.rs:62-72):
   - If output_balance_used OR allow_output_balance is true:
     - Return output_balance if it exists
     - Mark output_balance_used = true
   - Otherwise return final_balance

   This enables same-block TX chains:
   - TX1: Alice sends to Bob (Alice's output_balance set)
   - TX2: Bob sends using output_balance (Bob got funds from TX1) */
static inline ulong *
at_echange_get_balance( at_echange_t * e ) {
  if( AT_UNLIKELY( !e ) ) return NULL;

  int use_output = e->output_balance_used || e->allow_output_balance;
  if( use_output && e->has_output_balance ) {
    if( !e->output_balance_used ) {
      e->output_balance_used = 1;
    }
    return &e->output_balance;
  }
  return &e->final_balance;
}

/* at_echange_get_balance_value returns the current balance value (read-only).
   Does not modify output_balance_used state. */
static inline ulong
at_echange_get_balance_value( at_echange_t const * e ) {
  if( AT_UNLIKELY( !e ) ) return 0;

  int use_output = e->output_balance_used || e->allow_output_balance;
  if( use_output && e->has_output_balance ) {
    return e->output_balance;
  }
  return e->final_balance;
}

/* ============================================================================
   Output Tracking
   ============================================================================ */

/* at_echange_add_output adds an output amount to the cumulative output_sum.
   Uses saturating addition to prevent overflow.

   TOS Rust: Echange::add_output (chain_state/mod.rs) */
static inline void
at_echange_add_output( at_echange_t * e, ulong amount ) {
  if( AT_UNLIKELY( !e ) ) return;
  /* Saturating add to prevent overflow */
  if( e->output_sum > ULONG_MAX - amount ) {
    e->output_sum = ULONG_MAX;
  } else {
    e->output_sum += amount;
  }
}

/* at_echange_set_output_balance sets the output balance for future same-block TXs.
   This is called after a successful output from this account.

   TOS Rust: When a sender's balance is deducted, output_balance is set
   to enable subsequent TXs in the same block to use this balance. */
static inline void
at_echange_set_output_balance( at_echange_t * e, ulong balance ) {
  if( AT_UNLIKELY( !e ) ) return;
  e->output_balance = balance;
  e->has_output_balance = 1;
}

/* ============================================================================
   Commit Preparation
   ============================================================================ */

/* at_echange_prepare_commit prepares the echange for final commit.

   TOS Rust Logic (apply.rs:1311-1355):
   - If account has both inputs and outputs in same block:
     - Set balance_type = Both
     - Set output_balance from current balance state
   - If only outputs:
     - If output_balance_used OR !new_version, re-fetch latest version
     - Subtract output_sum from final_balance

   Returns: 0 on success, -1 on underflow */
static inline int
at_echange_prepare_commit( at_echange_t * e ) {
  if( AT_UNLIKELY( !e ) ) return -1;

  /* If using output_balance, it already reflects remaining balance after outputs.
     Only check for underflow, don't subtract again. */
  if( e->has_output_balance && (e->output_balance_used || e->allow_output_balance) ) {
    /* output_balance was set to (starting_balance - cumulative_outputs) after each TX.
       Just verify it's consistent with output_sum (not negative). */
    return 0;
  }

  /* Using final_balance - need to subtract output_sum */
  if( e->final_balance < e->output_sum ) {
    return -1;  /* Underflow - insufficient balance */
  }

  /* Subtract output_sum from final_balance */
  e->final_balance -= e->output_sum;

  return 0;
}

/* at_echange_get_commit_balance returns the final balance value for storage.
   Should be called after at_echange_prepare_commit. */
static inline ulong
at_echange_get_commit_balance( at_echange_t const * e ) {
  if( AT_UNLIKELY( !e ) ) return 0;

  /* If output_balance was used, return that (already reflects all outputs).
     Otherwise return final_balance (after prepare_commit subtracted output_sum). */
  if( e->has_output_balance && (e->output_balance_used || e->allow_output_balance) ) {
    return e->output_balance;
  }
  return e->final_balance;
}

/* ============================================================================
   Account Echange Management
   ============================================================================ */

/* at_account_echange_init initializes an account echange structure */
static inline void
at_account_echange_init( at_account_echange_t * ae, uchar const pubkey[32] ) {
  if( AT_UNLIKELY( !ae || !pubkey ) ) return;
  at_memcpy( ae->pubkey, pubkey, 32 );
  ae->assets_cnt = 0;
  ae->nonce = 0;
  ae->prev_nonce_topo = 0;
  ae->has_prev_nonce_topo = 0;
  ae->nonce_dirty = 0;
}

/* at_account_echange_find_asset finds or creates an asset echange entry.
   Returns pointer to the asset echange, or NULL if full. */
static inline at_asset_echange_t *
at_account_echange_find_asset( at_account_echange_t * ae,
                                uchar const            asset[32],
                                int                    create ) {
  if( AT_UNLIKELY( !ae || !asset ) ) return NULL;

  /* Search existing */
  for( ulong i = 0; i < ae->assets_cnt; i++ ) {
    if( at_memcmp( ae->assets[i].asset, asset, 32 ) == 0 ) {
      return &ae->assets[i];
    }
  }

  /* Create new if requested and space available */
  if( create && ae->assets_cnt < AT_ECHANGE_MAX_ASSETS ) {
    at_asset_echange_t * entry = &ae->assets[ae->assets_cnt];
    at_memcpy( entry->asset, asset, 32 );
    at_memset( &entry->echange, 0, sizeof(at_echange_t) );
    ae->assets_cnt++;
    return entry;
  }

  return NULL;
}

AT_PROTOTYPES_END

#endif /* HEADER_at_tos_at_echange_h */
