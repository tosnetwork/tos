#ifndef HEADER_at_vm_at_vm_providers_h
#define HEADER_at_vm_at_vm_providers_h

/* at_vm_providers.h - VM Provider Interfaces

   This module defines provider interfaces that connect VM syscalls to
   the actual blockchain state (at_rocks). Providers abstract the storage
   layer, allowing syscalls to work with different backends.

   Provider Types:
   - Storage Provider: Contract storage (read/write/delete)
   - Account Provider: Balance and nonce operations
   - Contract Loader: Load contract bytecode for CPI

   Supported Backends:
   - Rocks: TOS-compatible RocksDB storage (production)
   - Store: Generic at_store interface (memory backend)

   Usage (Rocks):
     at_vm_rocks_ctx_t rocks_ctx = { rocks, topoheight };
     at_vm_storage_provider_t storage;
     at_vm_storage_provider_init_rocks( &storage, &rocks_ctx );
*/

#include "at/core/storage/at_rocks.h"
#include "at/infra/at_flamenco_base.h"

struct at_store;
typedef struct at_store at_store_t;

AT_PROTOTYPES_BEGIN

/* ============================================================================
   Storage Provider Interface
   ============================================================================
   Provides contract storage operations (EVM-style SLOAD/SSTORE).
   Storage is keyed by (contract_address, slot_key) pairs.
   ============================================================================ */

/* Storage provider operations (function pointers) */
typedef struct at_vm_storage_provider at_vm_storage_provider_t;

struct at_vm_storage_provider {
  /* Read a 32-byte value from storage.
     Returns 0 on success, -1 if not found (value zeroed). */
  int (*read)( at_vm_storage_provider_t * self,
               uchar const                contract[32],
               uchar const                key[32],
               uchar                      value[32] );

  /* Write a 32-byte value to storage.
     Returns 0 on success, -1 on error. */
  int (*write)( at_vm_storage_provider_t * self,
                uchar const                contract[32],
                uchar const                key[32],
                uchar const                value[32] );

  /* Remove a key from storage.
     Returns 0 on success (even if key didn't exist), -1 on error. */
  int (*remove)( at_vm_storage_provider_t * self,
                 uchar const                contract[32],
                 uchar const                key[32] );

  /* Provider-specific context */
  void * ctx;
};

/* ============================================================================
   Account Provider Interface
   ============================================================================
   Provides account operations (balance, nonce, transfer).
   ============================================================================ */

typedef struct at_vm_account_provider at_vm_account_provider_t;

struct at_vm_account_provider {
  /* Get account balance.
     Returns balance, or 0 if account not found. */
  ulong (*get_balance)( at_vm_account_provider_t * self,
                        uchar const                address[32] );

  /* Transfer amount from sender to receiver.
     Returns 0 on success, -1 on error (insufficient balance, etc). */
  int (*transfer)( at_vm_account_provider_t * self,
                   uchar const                sender[32],
                   uchar const                receiver[32],
                   ulong                      amount );

  /* Get account nonce.
     Returns nonce, or 0 if account not found. */
  ulong (*get_nonce)( at_vm_account_provider_t * self,
                      uchar const                address[32] );

  /* Check if account exists.
     Returns 1 if exists, 0 otherwise. */
  int (*exists)( at_vm_account_provider_t * self,
                 uchar const                address[32] );

  /* Provider-specific context */
  void * ctx;
};

/* ============================================================================
   Contract Loader Interface
   ============================================================================
   Provides contract bytecode loading for CPI.
   ============================================================================ */

typedef struct at_vm_contract_loader at_vm_contract_loader_t;

struct at_vm_contract_loader {
  /* Load contract bytecode.
     Returns bytecode size, or 0 if contract not found.
     *bytecode_out points to the bytecode (valid until next load). */
  ulong (*load)( at_vm_contract_loader_t * self,
                 uchar const               contract_hash[32],
                 uchar const **            bytecode_out );

  /* Get contract code hash from account address.
     Returns 0 on success, -1 if not a contract. */
  int (*get_code_hash)( at_vm_contract_loader_t * self,
                        uchar const               address[32],
                        uchar                     code_hash[32] );

  /* Provider-specific context */
  void * ctx;
};

/* ============================================================================
   Rocks-backed Provider Context
   ============================================================================ */

/* Context for rocks-backed providers (TOS-compatible production storage) */
typedef struct {
  at_rocks_t * rocks;       /* RocksDB instance */
  ulong        topoheight;  /* Current topoheight for versioning */
} at_vm_rocks_ctx_t;

/* Context for store-backed providers (in-memory). */
typedef struct {
  at_store_t * store;       /* at_store instance (memory backend) */
  ulong        topoheight;  /* Current topoheight for versioning */
} at_vm_store_ctx_t;

/* ============================================================================
   Rocks-backed Provider Implementations (TOS-compatible)
   ============================================================================ */

/* Initialize a storage provider backed by rocks.
   The provider is valid as long as ctx and rocks remain valid. */
void
at_vm_storage_provider_init_rocks( at_vm_storage_provider_t * provider,
                                   at_vm_rocks_ctx_t *        ctx );

/* Initialize an account provider backed by rocks */
void
at_vm_account_provider_init_rocks( at_vm_account_provider_t * provider,
                                   at_vm_rocks_ctx_t *        ctx );

/* Initialize a contract loader backed by rocks */
void
at_vm_contract_loader_init_rocks( at_vm_contract_loader_t * loader,
                                  at_vm_rocks_ctx_t *       ctx );

/* ============================================================================
   Store-backed Provider Implementations (Memory backend)
   ============================================================================ */

void
at_vm_storage_provider_init_store( at_vm_storage_provider_t * provider,
                                   at_vm_store_ctx_t *        ctx );

void
at_vm_account_provider_init_store( at_vm_account_provider_t * provider,
                                   at_vm_store_ctx_t *        ctx );

void
at_vm_contract_loader_init_store( at_vm_contract_loader_t * loader,
                                  at_vm_store_ctx_t *       ctx );

/* ============================================================================
   Execution Context Management
   ============================================================================ */

/* Initialize an execution context for contract execution (rocks backend).
   This is the TOS-compatible version using RocksDB storage.

   Arguments:
     ctx       - Execution context to initialize
     rocks     - RocksDB instance for storage
     topoheight - Current topoheight for versioned storage
     contract  - Contract being executed (32-byte hash)
     tx_sender - Transaction sender (32-byte pubkey)
     tx_hash   - Transaction hash (32-byte)
     block_hash - Current block hash (32-byte)
     block_height - Current block height
     block_timestamp - Block timestamp (Unix seconds)
     chain_id  - Chain ID for replay protection

   Returns 0 on success, -1 on error. */
int
at_vm_exec_ctx_init_rocks( at_exec_instr_ctx_t * ctx,
                           at_rocks_t *          rocks,
                           ulong                 topoheight,
                           uchar const           contract[32],
                           uchar const           tx_sender[32],
                           uchar const           tx_hash[32],
                           uchar const           block_hash[32],
                           ulong                 block_height,
                           ulong                 block_timestamp,
                           ulong                 chain_id );

/* Initialize an execution context for contract execution (store backend).
   For in-memory backends that use at_store directly. */
int
at_vm_exec_ctx_init_store( at_exec_instr_ctx_t * ctx,
                           at_store_t *          store,
                           ulong                 topoheight,
                           uchar const           contract[32],
                           uchar const           tx_sender[32],
                           uchar const           tx_hash[32],
                           uchar const           block_hash[32],
                           ulong                 block_height,
                           ulong                 block_timestamp,
                           ulong                 chain_id );

/* Clean up an execution context.
   Frees any allocated resources (transient storage, etc). */
void
at_vm_exec_ctx_fini( at_exec_instr_ctx_t * ctx );

/* Allocate and initialize transient storage for a contract.
   Returns pointer to transient storage, or NULL on error. */
at_transient_storage_t *
at_vm_transient_storage_new( at_alloc_t * alloc,
                             uchar const contract[32] );

/* Free transient storage */
void
at_vm_transient_storage_delete( at_alloc_t *           alloc,
                                at_transient_storage_t * storage );

/* Initialize VRF context from block header VRF data.
   Arguments:
     ctx           - VRF context to initialize
     vrf_output    - 32-byte VRF output from block header
     vrf_proof     - 80-byte VRF proof from block header
     vrf_public_key - 32-byte VRF public key from block producer
     block_hash    - Current block hash (for instant_random derivation) */
void
at_vm_vrf_ctx_init( at_vrf_ctx_t * ctx,
                    uchar const    vrf_output[32],
                    uchar const    vrf_proof[80],
                    uchar const    vrf_public_key[32],
                    uchar const    block_hash[32] );

AT_PROTOTYPES_END

#endif /* HEADER_at_vm_at_vm_providers_h */