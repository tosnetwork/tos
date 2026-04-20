#ifndef HEADER_at_app_at_daemon_config_h
#define HEADER_at_app_at_daemon_config_h

#include "at/infra/at_util_base.h"

#include <stddef.h>
#include <stdint.h>

/* Simple config model aligned to tos/daemon (Rust) CLI + JSON config. */

typedef enum {
  AT_LOG_LEVEL_OFF = 0,
  AT_LOG_LEVEL_ERROR,
  AT_LOG_LEVEL_WARN,
  AT_LOG_LEVEL_INFO,
  AT_LOG_LEVEL_DEBUG,
  AT_LOG_LEVEL_TRACE
} at_log_level_t;

#ifndef AT_NETWORK_TYPE_DEFINED
#define AT_NETWORK_TYPE_DEFINED
typedef enum {
  AT_NETWORK_MAINNET = 0,
  AT_NETWORK_TESTNET,
  AT_NETWORK_STAGENET,
  AT_NETWORK_DEVNET
} at_network_t;
typedef at_network_t at_network_type_t;
#endif

typedef enum {
  AT_PROXY_KIND_NONE = 0,
  AT_PROXY_KIND_SOCKS5,
  AT_PROXY_KIND_SOCKS4
} at_proxy_kind_t;

typedef enum {
  AT_KEY_VERIFY_WARN = 0,
  AT_KEY_VERIFY_REJECT,
  AT_KEY_VERIFY_IGNORE
} at_key_verification_action_t;

typedef enum {
  AT_STORAGE_BACKEND_ROCKSDB = 0,
  AT_STORAGE_BACKEND_UNKNOWN
} at_storage_backend_t;

typedef enum {
  AT_SIMULATOR_NONE = 0,
  AT_SIMULATOR_BLOCKCHAIN,
  AT_SIMULATOR_BLOCKDAG,
  AT_SIMULATOR_STRESS
} at_simulator_t;

typedef enum {
  AT_COMPRESSION_NONE = 0,
  AT_COMPRESSION_SNAPPY,
  AT_COMPRESSION_ZLIB,
  AT_COMPRESSION_BZ2,
  AT_COMPRESSION_LZ4,
  AT_COMPRESSION_LZ4HC,
  AT_COMPRESSION_ZSTD
} at_compression_mode_t;

typedef enum {
  AT_CACHE_NONE = 0,
  AT_CACHE_LRU,
  AT_CACHE_HYPERCLOCK
} at_cache_mode_t;

typedef struct {
  char *         module;
  at_log_level_t level;
} at_module_config_t;

typedef struct {
  at_module_config_t * items;
  size_t               cnt;
  size_t               cap;
} at_module_config_list_t;

typedef struct {
  char ** items;
  size_t  cnt;
  size_t  cap;
} at_string_list_t;

typedef struct {
  at_log_level_t log_level;
  int            has_file_log_level;
  at_log_level_t file_log_level;
  int            disable_file_logging;
  int            disable_file_log_date_based;
  int            disable_log_color;
  int            disable_interactive_mode;
  int            auto_compress_logs;
  char *         filename_log;
  char *         logs_path;
  at_module_config_list_t logs_modules;
  int            disable_ascii_art;
  char *         datetime_format;
} at_log_config_t;

typedef struct {
  int    disable;
  uint64_t rate_limit_ms;
  size_t notify_job_concurrency;
} at_getwork_config_t;

typedef struct {
  int   enable;
  char *route;
} at_prometheus_config_t;

typedef struct {
  at_getwork_config_t     getwork;
  at_prometheus_config_t  prometheus;

  int    disable;
  char * bind_address;
  size_t threads;
  size_t notify_events_concurrency;
  uint64_t stop_timeout_secs;

  char * ws_allowed_origins; /* NULL => unset */
  int    ws_require_auth;
  size_t ws_max_message_size;
  size_t ws_max_subscriptions;
  uint32_t ws_max_connections_per_minute;
  uint32_t ws_max_messages_per_second;

  int    enable_admin_rpc;
  char * admin_token; /* NULL => unset */

} at_rpc_config_t;

typedef struct {
  char *         address;
  at_proxy_kind_t kind;
  int            has_kind;
  char *         username;
  char *         password;
} at_proxy_config_t;

/* Discovery (discv6) configuration */
typedef struct {
  int    disable;                   /* --disable-discovery */
  int    discovery_only;            /* --p2p-discovery-only (bootnode mode) */
  uint16_t port;                    /* --discovery-port (default: 2126) */
  char * bind_address;              /* --discovery-bind-address (e.g. 0.0.0.0:2126) */
  char * private_key;               /* --discovery-private-key (hex) */
  at_string_list_t bootstrap;       /* --discovery-bootstrap (tosnode:// URLs) */
  size_t bucket_size;               /* --discovery-bucket-size (default: 16) */
} at_discovery_config_t;

typedef struct {
  at_proxy_config_t proxy;
  char * tag;
  char * bind_address;
  size_t max_peers;
  size_t max_outgoing_peers;
  at_string_list_t priority_nodes;
  at_string_list_t exclusive_nodes;
  at_string_list_t bootstrap_nodes;
  int    disable;
  int    allow_fast_sync;
  int    allow_boost_sync;
  int    allow_priority_blocks;
  size_t max_chain_response_size;
  int    disable_ip_sharing;
  size_t concurrency_task_count_limit;
  at_key_verification_action_t on_dh_key_change;
  char * dh_private_key;
  size_t stream_concurrency;
  char * temp_ban_duration; /* human-readable duration, e.g. "15m" */
  uint8_t fail_count_limit;
  size_t dh_db_wksp_pages;
  size_t dh_db_wksp_part_max;
  int    disable_reexecute_blocks_on_sync;
  at_log_level_t block_propagation_log_level;
  int    disable_fetching_txs_propagated;
  int    handle_peer_packets_in_dedicated_task;
  int    disable_fast_sync_support;
  int    sync_from_priority_only;
  int    reorg_from_priority_only;
  at_discovery_config_t discovery;  /* Discv6 peer discovery config */
} at_p2p_config_t;

typedef struct {
  size_t parallelism;
  size_t max_background_jobs;
  size_t max_subcompaction_jobs;
  size_t low_priority_background_threads;
  int    max_open_files;
  size_t keep_max_log_files;
  at_compression_mode_t compression_mode;
  at_cache_mode_t cache_mode;
  uint64_t cache_size;
  uint64_t write_buffer_size;
  int    write_buffer_shared;
} at_rocksdb_config_t;

typedef struct {
  char * private_key;
  char * miner_private_key;
  at_string_list_t allowed_public_keys;
} at_vrf_config_t;

typedef struct {
  at_rpc_config_t     rpc;
  at_p2p_config_t     p2p;
  at_rocksdb_config_t rocksdb;
  at_vrf_config_t     vrf;

  char * dir_path;
  at_simulator_t simulator;
  int    has_simulator;
  int    skip_pow_verification;
  int    has_auto_prune_keep_n_blocks;
  uint64_t auto_prune_keep_n_blocks;
  int    skip_block_template_txs_verification;
  char * genesis_block_hex;
  at_string_list_t checkpoints;
  size_t txs_verification_threads_count;
  int    check_db_integrity;
  int    recovery_mode;
  int    has_flush_db_every_n_blocks;
  uint64_t flush_db_every_n_blocks;
  at_storage_backend_t use_db_backend;
  int    disable_zkp_cache;
} at_core_config_t;

typedef struct {
  int sandbox;  /* Enable sandbox (default: 1). Set to 0 to disable sandboxing for development. */
} at_development_config_t;

typedef struct {
  at_core_config_t        core;
  at_log_config_t         log;
  at_development_config_t development;
  at_network_t            network;

  char * config_file; /* CLI only */
  int    generate_config_template; /* CLI only */
} at_cli_config_t;

AT_PROTOTYPES_BEGIN

void
at_daemon_config_init( at_cli_config_t * cfg );

void
at_daemon_config_free( at_cli_config_t * cfg );

int
at_daemon_config_load_json_file( char const * path, at_cli_config_t * cfg, char * err_buf, size_t err_buf_sz );

int
at_daemon_config_write_json_file( char const * path, at_cli_config_t const * cfg, char * err_buf, size_t err_buf_sz );

int
at_daemon_config_apply_cli( int argc, char ** argv, at_cli_config_t * cfg, char * err_buf, size_t err_buf_sz );

void *
at_daemon_config_alloc( ulong align, ulong sz );

void
at_daemon_config_dealloc( void * ptr );

char const *
at_daemon_log_level_to_str( at_log_level_t level );

char const *
at_daemon_network_to_str( at_network_t network );

AT_PROTOTYPES_END

#endif /* HEADER_at_app_at_daemon_config_h */
