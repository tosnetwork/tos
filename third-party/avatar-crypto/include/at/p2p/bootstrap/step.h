#ifndef HEADER_at_waltz_p2p_bootstrap_step_h
#define HEADER_at_waltz_p2p_bootstrap_step_h

#include "at/infra/at_util_base.h"
#include "at/account/at_account.h"

#ifndef AT_BOOTSTRAP_CHAIN_INFO_MAX_BLOCKS
#ifdef AT_CHAIN_REQUEST_MAX_BLOCKS
#define AT_BOOTSTRAP_CHAIN_INFO_MAX_BLOCKS (AT_CHAIN_REQUEST_MAX_BLOCKS)
#else
#define AT_BOOTSTRAP_CHAIN_INFO_MAX_BLOCKS (64)
#endif
#endif

#define AT_BOOTSTRAP_MAX_ITEMS_PER_PAGE (1024)
#define AT_BOOTSTRAP_MAX_STR_LEN        (255)
#define AT_BOOTSTRAP_MAX_MULTISIG_PARTICIPANTS (255)

AT_PROTOTYPES_BEGIN

typedef enum {
  AT_BOOTSTRAP_STEP_CHAIN_INFO    = 0,
  AT_BOOTSTRAP_STEP_ASSETS        = 1,
  AT_BOOTSTRAP_STEP_KEYS          = 2,
  AT_BOOTSTRAP_STEP_KEY_BALANCES  = 3,
  AT_BOOTSTRAP_STEP_SPENDABLE_BALANCES = 4,
  AT_BOOTSTRAP_STEP_ACCOUNTS      = 5,
  AT_BOOTSTRAP_STEP_CONTRACTS     = 6,
  AT_BOOTSTRAP_STEP_CONTRACT_MODULE = 7,
  AT_BOOTSTRAP_STEP_CONTRACT_BALANCES = 8,
  AT_BOOTSTRAP_STEP_CONTRACT_STORES = 9,
  AT_BOOTSTRAP_STEP_BLOCKS_METADATA = 10,
  AT_BOOTSTRAP_STEP_ASSETS_SUPPLY = 11,
  AT_BOOTSTRAP_STEP_CONTRACTS_EXECUTIONS = 12
} at_bootstrap_step_kind_t;

typedef struct {
  uchar  hash[32];
  ulong  topoheight;
} at_bootstrap_block_id_t;

typedef struct {
  uchar  has_common; /* 0=None, 1=Some */
  uchar  hash[32];
  ulong  topoheight;
} at_bootstrap_common_point_t;

typedef struct {
  uchar contract[32];
  ulong id;
} at_bootstrap_asset_owner_t;

typedef struct {
  uchar  decimals;
  uchar  name_len;
  char   name[AT_BOOTSTRAP_MAX_STR_LEN + 1];
  uchar  ticker_len;
  char   ticker[AT_BOOTSTRAP_MAX_STR_LEN + 1];
  uchar  has_max_supply;
  ulong  max_supply;
  uchar  has_owner;
  at_bootstrap_asset_owner_t owner;
} at_bootstrap_asset_data_t;

typedef struct {
  uchar  has_output_topoheight;
  ulong  output_topoheight;
  ulong  stable_topoheight;
} at_bootstrap_account_summary_t;

typedef struct {
  uchar  state_tag; /* 0=Clean,1=Some,2=None,3=Deleted */
  ulong  nonce;     /* valid if state_tag==1 */
} at_bootstrap_state_nonce_t;

typedef struct {
  uchar  state_tag; /* 0=Clean,1=Some,2=None,3=Deleted */
  uchar  threshold;
  uchar  participants_cnt;
  uchar (*participants)[32]; /* valid if state_tag==1 && threshold!=0 */
} at_bootstrap_state_multisig_t;

typedef struct {
  uchar                        asset[32];
  at_bootstrap_account_summary_t summary;
  uchar                        has_summary;
} at_bootstrap_key_balance_t;

typedef struct {
  uchar                      asset[32];
  at_bootstrap_asset_data_t  data;
} at_bootstrap_asset_entry_t;

typedef struct {
  at_bootstrap_state_nonce_t    nonce_state;
  at_bootstrap_state_multisig_t multisig_state;
} at_bootstrap_account_entry_t;

typedef struct {
  at_bootstrap_step_kind_t kind;
  union {
    struct {
      at_bootstrap_block_id_t const * blocks;
      uchar                           block_cnt;
    } chain_info;
    struct {
      ulong min_topoheight;
      ulong max_topoheight;
      int   has_page;
      ulong page;
    } assets;
    struct {
      ulong stable_topoheight;
      uchar const (*assets)[32];
      ushort asset_cnt;
    } assets_supply;
    struct {
      ulong min_topoheight;
      ulong max_topoheight;
      int   has_page;
      ulong page;
    } keys;
    struct {
      uchar key[32];
      uchar asset[32];
      ulong min_topoheight;
      ulong max_topoheight;
    } spendable_balances;
    struct {
      uchar key[32];
      ulong min_topoheight;
      ulong max_topoheight;
      int   has_page;
      ulong page;
    } key_balances;
    struct {
      ulong min_topoheight;
      ulong max_topoheight;
      uchar const (*keys)[32];
      ushort key_cnt;
    } accounts;
    struct {
      ulong min_topoheight;
      ulong max_topoheight;
      int   has_page;
      ulong page;
    } contracts;
    struct {
      ulong min_topoheight;
      ulong max_topoheight;
      uchar contract[32];
    } contract_module;
    struct {
      uchar contract[32];
      ulong topoheight;
      int   has_page;
      ulong page;
    } contract_balances;
    struct {
      uchar contract[32];
      ulong topoheight;
      int   has_page;
      ulong page;
    } contract_stores;
    struct {
      ulong min_topoheight;
      ulong max_topoheight;
      int   has_page;
      ulong page;
    } contracts_executions;
    struct {
      ulong topoheight;
    } blocks_metadata;
  } u;
} at_bootstrap_step_req_t;

typedef struct {
  uchar has_value;
  ulong value;
} at_bootstrap_opt_u64_t;

typedef struct {
  ulong topoheight;
  int   has_output_balance;
  ulong output_balance;
  ulong final_balance;
  at_balance_type_t balance_type;
} at_bootstrap_balance_t;

typedef struct {
  at_bootstrap_step_kind_t kind;
  union {
    struct {
      at_bootstrap_common_point_t common_point;
      ulong topoheight;
      ulong stable_height;
      uchar top_hash[32];
    } chain_info;
    struct {
      at_bootstrap_asset_entry_t const * entries;
      ushort                             entry_cnt;
      int                                has_page;
      ulong                              page;
    } assets;
    struct {
      at_bootstrap_opt_u64_t const * entries;
      ushort                         entry_cnt;
    } assets_supply;
    struct {
      uchar const (*keys)[32];
      ushort      key_cnt;
      int         has_page;
      ulong       page;
    } keys;
    struct {
      at_bootstrap_key_balance_t const * entries;
      ushort                             entry_cnt;
      int                                has_page;
      ulong                              page;
    } key_balances;
    struct {
      at_bootstrap_balance_t const * entries;
      ushort                         entry_cnt;
      int                            has_next_topoheight;
      ulong                          next_topoheight;
    } spendable_balances;
    struct {
      at_bootstrap_account_entry_t const * entries;
      ushort                               entry_cnt;
    } accounts;
    struct {
      uchar const (*contracts)[32];
      ushort      contract_cnt;
      int         has_page;
      ulong       page;
    } contracts;
    struct {
      uchar  state_tag;
      uchar const * module;
      ulong module_sz;
    } contract_module;
    struct {
      uchar const (*assets)[32];
      ulong const * balances;
      ushort        entry_cnt;
      int           has_page;
      ulong         page;
    } contract_balances;
    struct {
      uchar const * keys;
      ulong const * keys_sz;
      uchar const * values;
      ulong const * values_sz;
      ushort        entry_cnt;
      int           has_page;
      ulong         page;
    } contract_stores;
    struct {
      uchar const * entries;
      ulong const * entry_sz;
      ushort        entry_cnt;
      int           has_page;
      ulong         page;
    } contracts_executions;
    struct {
      uchar const * entries;
      ulong const * entry_sz;
      ushort        entry_cnt;
    } blocks_metadata;
  } u;
} at_bootstrap_step_resp_t;

typedef struct {
  at_bootstrap_block_id_t * blocks;
  ulong                     blocks_cap;
  uchar (*                  assets)[32];
  ulong                     assets_cap;
  uchar (*                  keys)[32];
  ulong                     keys_cap;
} at_bootstrap_step_req_bufs_t;

typedef struct {
  at_bootstrap_asset_entry_t * assets;
  ulong                        assets_cap;
  at_bootstrap_opt_u64_t *     assets_supply;
  ulong                        assets_supply_cap;
  uchar (*                     keys)[32];
  ulong                        keys_cap;
  at_bootstrap_key_balance_t * key_balances;
  ulong                        key_balances_cap;
  at_bootstrap_balance_t *     spendable_balances;
  ulong                        spendable_balances_cap;
  at_bootstrap_account_entry_t * accounts;
  ulong                         accounts_cap;
  uchar (*                      contracts)[32];
  ulong                         contracts_cap;
  uchar *                       contract_module_buf;
  ulong                         contract_module_cap;
  ulong                         contract_module_used;
  uchar *                       contract_balance_assets_buf;
  ulong                         contract_balance_assets_cap;
  ulong *                       contract_balance_values;
  ulong                         contract_balance_values_cap;
  uchar *                       contract_store_keys_buf;
  ulong *                       contract_store_keys_sz;
  ulong                         contract_store_keys_cap;
  uchar *                       contract_store_vals_buf;
  ulong *                       contract_store_vals_sz;
  ulong                         contract_store_vals_cap;
  uchar *                       contracts_exec_buf;
  ulong *                       contracts_exec_sz;
  ulong                         contracts_exec_cap;
  uchar *                       blocks_metadata_buf;
  ulong *                       blocks_metadata_sz;
  ulong                         blocks_metadata_cap;
  uchar *                       multisig_participants_buf;
  ulong                         multisig_participants_cap;
  ulong                         multisig_participants_used;
} at_bootstrap_step_resp_bufs_t;

long
at_bootstrap_step_req_serialize( at_bootstrap_step_req_t const * req,
                                 uchar *                       buf,
                                 ulong                         buf_sz );

int
at_bootstrap_step_req_deserialize( uchar const *               buf,
                                   ulong                       buf_sz,
                                   at_bootstrap_step_req_t *   out_req,
                                   at_bootstrap_step_req_bufs_t * bufs );

long
at_bootstrap_step_resp_serialize( at_bootstrap_step_resp_t const * resp,
                                  uchar *                          buf,
                                  ulong                            buf_sz );

int
at_bootstrap_step_resp_deserialize( uchar const *                buf,
                                    ulong                        buf_sz,
                                    at_bootstrap_step_resp_t *   out_resp,
                                    at_bootstrap_step_resp_bufs_t * bufs );

AT_PROTOTYPES_END

#endif /* HEADER_at_waltz_p2p_bootstrap_step_h */
