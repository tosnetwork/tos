#!/usr/bin/env bash
# Opt-in validator role for the container entrypoint.
#
# The container runs a full node unless both of these are set:
#
#   VALIDATOR_ID            the controller account's 256-bit id: 64 hex digits,
#                           or its masterchain address -1:<64 hex digits>
#   PQ_CONSENSUS_KEY_FILE   absolute path, inside the container, of the mounted
#                           32-byte post-quantum consensus seed
#
# With both set, `apply` records them as extraconfig.pq_consensus in the
# node's config.json, which makes the engine load the key and act as that
# validator. Setting only one of them is refused rather than guessed at.
#
#   validator-role.sh check CONFIG   validate the environment and CONFIG (which
#                                    may not exist yet); changes nothing
#   validator-role.sh apply CONFIG   check, then bind; CONFIG is DB_ROOT/config.json
#
# The binding is written by `tos-pq-consensus-key bind-node`, the one writer of
# that block: it holds DB_ROOT/config.json.lock (which a running node holds
# too), writes through the engine's own schema and refuses content that schema
# would drop, flushes the file and its directory, and checks the key again
# under the rules the node loads it by. This script does not edit config.json;
# it reads it and leaves the binding to bind-node. (init.sh's own first-start
# steps, the console control and lite server entries, still edit config.json
# with sed, before this script binds.) TOS_PQ_CONSENSUS_KEY_TOOL names another
# binary.
#
# The role is in effect when the variables are set or when CONFIG already
# binds a validator: a node bound on an earlier start stays a validator after
# the variables are removed, and the same rules apply to it.
#
# The key file is checked with the rules the engine itself applies when it
# loads a seed: not a symbolic link, a regular file of exactly 32 bytes, owned
# by the effective user, no group or other permission bits, in a directory
# that is not group- or world-writable. A key that fails them is refused here,
# before the node starts, instead of by the engine after it has started. The
# seed's content is never read or printed by this script.
#
# A validator serves no public queries. With the role in effect this refuses
# LITESERVER, lite servers already configured in CONFIG, and any
# --json-rpc-address in CUSTOM_ARG that is not a literal loopback address
# (127.0.0.0/8 or [::1]); a host name is refused because the engine resolves
# it. CUSTOM_ARG is split exactly as init.sh expands it for the engine, and
# for every role it may not move the database or configuration (-D/--db,
# -c/--local-config). When CONFIG is missing, CONFIG.tmp, which the engine
# recovers, is inspected in its place.
#
# The binding is written once. A config.json that already names a different
# validator or key file is refused, not rewritten: changing the identity a
# node signs for is a deliberate operator edit, never a side effect of a
# changed environment variable.

set -euo pipefail

SEED_BYTES=32

refuse() {
  echo "VALIDATOR_ROLE_REFUSED: $*" >&2
  exit 1
}

role_requested() {
  [ -n "${VALIDATOR_ID:-}" ] || [ -n "${PQ_CONSENSUS_KEY_FILE:-}" ]
}

normalized_validator_id() {
  local id="${VALIDATOR_ID:-}"
  # The controller lives on the masterchain; its address form names it too.
  id="${id#-1:}"
  if [[ ! "$id" =~ ^[0-9A-Fa-f]{64}$ ]]; then
    refuse "VALIDATOR_ID must be exactly 64 hexadecimal digits, or -1: followed by them (the controller account id)"
  fi
  id="${id,,}"
  if [[ "$id" =~ ^0{64}$ ]]; then
    refuse "VALIDATOR_ID is zero; it must name the controller account"
  fi
  printf '%s' "$id"
}

check_key_file() {
  local path="${PQ_CONSENSUS_KEY_FILE:-}"
  [ -n "$path" ] || refuse "PQ_CONSENSUS_KEY_FILE is not set; VALIDATOR_ID needs the consensus key it signs with"
  [[ "$path" == /* ]] || refuse "PQ_CONSENSUS_KEY_FILE must be an absolute path, got $path"
  [ ! -L "$path" ] || refuse "consensus key $path is a symbolic link; mount the key file itself"
  [ -e "$path" ] || refuse "consensus key $path does not exist; mount it into the container"
  [ -f "$path" ] || refuse "consensus key $path is not a regular file"
  local owner mode size
  owner="$(stat -c '%u' -- "$path")" || refuse "cannot stat consensus key $path"
  mode="$(stat -c '%a' -- "$path")" || refuse "cannot stat consensus key $path"
  size="$(stat -c '%s' -- "$path")" || refuse "cannot stat consensus key $path"
  [ "$owner" = "$(id -u)" ] ||
    refuse "consensus key $path is owned by uid $owner, not by the node's uid $(id -u)"
  (((8#$mode & 8#077) == 0)) ||
    refuse "consensus key $path has mode $mode; it must have no group or other permissions (chmod 600)"
  [ "$size" = "$SEED_BYTES" ] ||
    refuse "consensus key $path holds $size bytes; a consensus seed is exactly $SEED_BYTES bytes"
  local directory dir_mode
  directory="$(dirname -- "$path")"
  dir_mode="$(stat -L -c '%a' -- "$directory")" || refuse "cannot stat directory $directory"
  (((8#$dir_mode & 8#022) == 0)) ||
    refuse "directory $directory of the consensus key is group- or world-writable (mode $dir_mode)"
}

# A literal loopback IP and a port: 127.a.b.c:port or [::1]:port. Anything
# else, host names included, is not provably loopback.
loopback_address() {
  local value="$1" host port octet
  case "$value" in
    "[::1]":*) port="${value#\[::1\]:}" ;;
    *:*)
      host="${value%:*}"
      port="${value##*:}"
      [[ "$host" =~ ^127\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
      for octet in "${BASH_REMATCH[@]:1}"; do
        ((10#$octet <= 255)) || return 1
      done
      ;;
    *) return 1 ;;
  esac
  [[ "$port" =~ ^[0-9]{1,5}$ ]] && ((10#$port >= 1 && 10#$port <= 65535))
}

# The words the engine receives from CUSTOM_ARG. init.sh passes $CUSTOM_ARG
# unquoted, so they are the result of its word splitting and pathname
# expansion, from the same directory; never only its first line.
custom_words() {
  # shellcheck disable=SC2206
  CUSTOM_WORDS=(${CUSTOM_ARG:-})
}

# The engine takes its database from the last -D/--db and its configuration
# from that database, or from -c/--local-config when no config.json exists
# there yet. init.sh names both, and CUSTOM_ARG follows them on the command
# line, so a later one there would make the engine run from a database and
# configuration this script never inspected. Refused for every role.
#
# To see what the engine sees, CUSTOM_ARG's words are parsed with the
# engine's own command-line algorithm (td::OptionParser::run), over the
# engine's own option table (the registrations in validator-engine.cpp;
# test_docker_validator_role.py fails if they drift apart):
#   - a word not starting with '-', or "-" alone, is not an option;
#   - "--" ends the options: every later word is not an option;
#   - "--name=value" or "--name": an option that takes an argument takes
#     the text after '=' or else the whole next word, whatever it starts
#     with; a flag given "=value" is an error;
#   - "-abc": letters are short options in turn; one that takes an
#     argument takes the rest of the word, or the whole next word when it
#     ends the word, and ends the bundle.
# An unknown option, a flag with a value or a missing argument is refused:
# the engine would refuse to start on it too. The words before CUSTOM_ARG
# on init.sh's command line are complete options with their values, so the
# engine starts CUSTOM_ARG in the same state as this parser does.
LONG_OPTIONS_WITH_ARGUMENT="
  verbosity
  measurement-jsonl
  measurement-node-id
  global-config
  local-config
  ip
  db
  fift-dir
  logname
  state-ttl
  mempool-num
  block-ttl
  archive-ttl
  key-proof-ttl
  sync-before
  truncate-db
  session-logs
  unsafe-catchain-restore
  unsafe-catchain-rotate
  add-shard
  threads
  user
  shutdown-at
  celldb-compress-depth
  max-archive-fd
  archive-preload-period
  celldb-cache-size
  celldb-cache-min-size
  celldb-cell-cache-max-size
  catchain-max-block-delay
  catchain-max-block-delay-slow
  collect-validator-telemetry
  broadcast-speed-catchain
  broadcast-speed-public
  broadcast-speed-private
  broadcast-speed-fast-sync
  initial-sync-delay
  fullnode-ratelimit-window-size
  fullnode-ratelimit-global
  fullnode-ratelimit-heavy
  fullnode-ratelimit-medium
  full-node-master-trusted
  auto-sign
  accept-certs-from
  sync-shards-upto
  shard-block-retainer
  db-event-fifo
  health-node-id
  health-diagnostic
  exporter-address
  json-rpc-address
  json-rpc-cors-origin
  json-rpc-readyz-threshold
  json-rpc-request-timeout
  json-rpc-response-timeout
  json-rpc-api-key
  json-rpc-cache-ttl
  json-rpc-trusted-proxy
  quic-flood-control
  persistent-state-download-cap
  persistent-state-processing-cap
  persistent-state-single-file-cap
  persistent-state-resident-cap
  persistent-state-max-returned-dag-bytes-per-parse
  persistent-state-max-cells-per-parse
  persistent-state-max-scaffolding-bytes-per-parse
  persistent-state-max-total-cell-bytes-per-parse
  persistent-state-spool-per-import-cap
  persistent-state-spool-total-cap
  persistent-state-spool-reservation-ratio-percent
"
LONG_OPTIONS_WITHOUT_ARGUMENT="
  version
  help
  daemonize
  enable-validator-consensus-cleanup
  test-consensus-cleanup-crash-before-erase
  not-all-shards
  enable-precompiled-smc
  disable-rocksdb-stats
  nonfinal-ls
  celldb-direct-io
  celldb-preload-all
  celldb-in-memory
  celldb-v2
  celldb-disable-bloom-filter
  unsynced-liteserver
  fast-state-serializer
  disable-state-serializer
  permanent-celldb
  skip-key-sync
  parallel-validation
  health-native-core-v2
  health-native-core-v3
  health-core-metrics
  json-rpc-readonly
  json-rpc-expose-consensus-status
  json-rpc-trust-proxy-headers
  persistent-state-allow-oversize-single-file
  dht-server
"
SHORT_OPTIONS="v=verbosity V=version h=help C=global-config c=local-config I=ip D=db f=fift-dir d=daemonize l=logname s=state-ttl m=mempool-num b=block-ttl A=archive-ttl K=key-proof-ttl S=sync-before T=truncate-db U=unsafe-catchain-restore F=unsafe-catchain-rotate M=not-all-shards t=threads u=user"

# The options CUSTOM_ARG gives the engine, as long names and values, in order.
ENGINE_OPTION_NAMES=()
ENGINE_OPTION_VALUES=()

long_option_kind() {
  local name="$1"
  if [[ "$LONG_OPTIONS_WITH_ARGUMENT" == *$'\n'"  $name"$'\n'* ]]; then
    echo argument
  elif [[ "$LONG_OPTIONS_WITHOUT_ARGUMENT" == *$'\n'"  $name"$'\n'* ]]; then
    echo flag
  else
    echo unknown
  fi
}

short_option_name() {
  local letter="$1" entry
  for entry in $SHORT_OPTIONS; do
    if [ "${entry%%=*}" = "$letter" ]; then
      printf '%s' "${entry#*=}"
      return 0
    fi
  done
  return 1
}

parse_engine_options() {
  ENGINE_OPTION_NAMES=()
  ENGINE_OPTION_VALUES=()
  local count=${#CUSTOM_WORDS[@]} i=0 j word name value kind letter
  while ((i < count)); do
    word="${CUSTOM_WORDS[i]}"
    i=$((i + 1))
    if [[ "$word" != -* || "$word" == "-" ]]; then
      continue
    fi
    if [ "$word" = "--" ]; then
      break
    fi
    if [[ "$word" == --* ]]; then
      name="${word#--}"
      value=""
      local has_value=no
      if [[ "$name" == *=* ]]; then
        value="${name#*=}"
        name="${name%%=*}"
        has_value=yes
      fi
      kind="$(long_option_kind "$name")"
      case "$kind" in
        argument)
          if [ "$has_value" = no ]; then
            ((i < count)) || refuse "CUSTOM_ARG ends with --$name, which needs a value"
            value="${CUSTOM_WORDS[i]}"
            i=$((i + 1))
          fi
          ;;
        flag)
          [ "$has_value" = no ] || refuse "CUSTOM_ARG gives a value to --$name, which takes none"
          ;;
        *) refuse "CUSTOM_ARG word '$word' is not a validator-engine option" ;;
      esac
      ENGINE_OPTION_NAMES+=("$name")
      ENGINE_OPTION_VALUES+=("$value")
      continue
    fi
    for ((j = 1; j < ${#word}; j++)); do
      letter="${word:j:1}"
      name="$(short_option_name "$letter")" ||
        refuse "CUSTOM_ARG word '$word' uses -$letter, which is not a validator-engine option"
      value=""
      if [ "$(long_option_kind "$name")" = argument ]; then
        if ((j + 1 < ${#word})); then
          value="${word:j+1}"
        else
          ((i < count)) || refuse "CUSTOM_ARG ends with -$letter, which needs a value"
          value="${CUSTOM_WORDS[i]}"
          i=$((i + 1))
        fi
        ENGINE_OPTION_NAMES+=("$name")
        ENGINE_OPTION_VALUES+=("$value")
        break
      fi
      ENGINE_OPTION_NAMES+=("$name")
      ENGINE_OPTION_VALUES+=("")
    done
  done
}

check_custom_arg_keeps_location() {
  local i
  for ((i = 0; i < ${#ENGINE_OPTION_NAMES[@]}; i++)); do
    case "${ENGINE_OPTION_NAMES[i]}" in
      db | local-config)
        refuse "CUSTOM_ARG sets --${ENGINE_OPTION_NAMES[i]} '${ENGINE_OPTION_VALUES[i]}'; the database and its configuration are fixed by the entrypoint"
        ;;
    esac
  done
}

# The configuration the engine will load from CONFIG's location: CONFIG, or,
# when it is missing, the CONFIG.tmp the engine then recovers and renames into
# place. Empty when neither exists.
effective_config() {
  local config="$1"
  if [ -e "$config" ] || [ -L "$config" ]; then
    printf '%s' "$config"
  elif [ -e "$config.tmp" ] || [ -L "$config.tmp" ]; then
    printf '%s' "$config.tmp"
  fi
}

# Whether CONFIG already binds a validator. A config that cannot be read is
# refused rather than taken as unbound.
config_binds_validator() {
  local config="$1"
  [ -n "$config" ] || return 1
  command -v jq >/dev/null || refuse "jq is required to read $config"
  local bound
  bound="$(jq -r 'if (.extraconfig.pq_consensus | type) == "object" then "yes" else "no" end' \
    "$config")" || refuse "cannot parse $config"
  [ "$bound" = "yes" ]
}

check_no_public_service() {
  local config="$1"
  if [ -n "${LITESERVER:-}" ]; then
    refuse "LITESERVER is set; a validator runs no lite server. Serve queries from a separate RPC node"
  fi
  if [ -n "$config" ]; then
    command -v jq >/dev/null || refuse "jq is required to read $config"
    local lite
    lite="$(jq -r '(.liteservers // []) | length' "$config")" || refuse "cannot parse $config"
    [ "$lite" = "0" ] ||
      refuse "$config configures $lite lite server(s); a validator runs none. Remove them from config.json"
  fi
  local i value
  for ((i = 0; i < ${#ENGINE_OPTION_NAMES[@]}; i++)); do
    [ "${ENGINE_OPTION_NAMES[i]}" = json-rpc-address ] || continue
    value="${ENGINE_OPTION_VALUES[i]}"
    loopback_address "$value" ||
      refuse "CUSTOM_ARG binds JSON-RPC to '$value'; a validator may bind it to loopback only"
  done
}

check() {
  local config effective
  config="$1"
  custom_words
  parse_engine_options
  check_custom_arg_keeps_location
  effective="$(effective_config "$config")"
  if ! role_requested; then
    if ! config_binds_validator "$effective"; then
      echo "[=] Validator role disabled (VALIDATOR_ID and PQ_CONSENSUS_KEY_FILE are not set)"
      return 0
    fi
    check_no_public_service "$effective"
    echo "[=] $effective already binds a validator; the validator role stays in effect"
    return 0
  fi
  [ -n "${VALIDATOR_ID:-}" ] ||
    refuse "PQ_CONSENSUS_KEY_FILE is set without VALIDATOR_ID; both are needed for the validator role"
  normalized_validator_id >/dev/null
  check_key_file
  check_no_public_service "$effective"
  echo "[+] Validator role: controller $(normalized_validator_id), consensus key $PQ_CONSENSUS_KEY_FILE"
}

apply() {
  local config="$1"
  check "$config"
  role_requested || return 0
  [ "$(basename -- "$config")" = config.json ] ||
    refuse "apply takes the node's DB_ROOT/config.json, not $config"
  [ -f "$config" ] || refuse "node config $config does not exist; initialize the node first"
  local tool="${TOS_PQ_CONSENSUS_KEY_TOOL:-tos-pq-consensus-key}"
  command -v "$tool" >/dev/null || refuse "$tool is not installed; it is what writes the binding"
  local output status
  # Never with bind-node's replace flag: a different existing binding stops
  # the container, so the identity a node signs for changes only by a
  # deliberate operator command.
  set +e
  output="$("$tool" bind-node "$(dirname -- "$config")" "$PQ_CONSENSUS_KEY_FILE" \
    "$(normalized_validator_id)" 2>&1)"
  status=$?
  set -e
  case "$status" in
    0)
      printf '%s\n' "$output"
      echo "[+] Validator binding in $config"
      ;;
    3)
      # In place, but bind-node's flush of the directory failed. A bare sync(2)
      # reports nothing, so it proves nothing: fsync the configuration and its
      # directory again with sync FILE..., which reports each failure, and
      # start only if both succeed.
      printf '%s\n' "$output" >&2
      if ! sync -- "$config" "$(dirname -- "$config")"; then
        refuse "the binding in $config is in place but could not be flushed to disk; the node was not started. Check the volume's health and free space (dmesg, df), then restart the container: the binding is kept, and a binding a crash lost is written again on the next start"
      fi
      echo "[+] Validator binding in $config (bind-node could not confirm it on disk; flushed again and confirmed)"
      ;;
    2)
      refuse "$tool has no usable bind-node command (exit 2); install a key tool that can bind a node"
      ;;
    *)
      refuse "bind-node refused, nothing was written: $output"
      ;;
  esac
}

case "${1:-}" in
  check)
    [ $# -eq 2 ] || refuse "usage: $0 check CONFIG"
    check "$2"
    ;;
  apply)
    [ $# -eq 2 ] || refuse "usage: $0 apply CONFIG"
    apply "$2"
    ;;
  *) refuse "usage: $0 check CONFIG | apply CONFIG" ;;
esac
