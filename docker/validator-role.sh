#!/usr/bin/env bash
# Opt-in validator role for the container entrypoint.
#
# The container runs a full node unless both of these are set:
#
#   VALIDATOR_ID            the controller account's 256-bit id, 64 hex digits
#   PQ_CONSENSUS_KEY_FILE   absolute path, inside the container, of the mounted
#                           32-byte post-quantum consensus seed
#
# With both set, `apply` records them as extraconfig.pq_consensus in the
# node's config.json, which makes the engine load the key and act as that
# validator. Setting only one of them is refused rather than guessed at.
#
#   validator-role.sh check CONFIG   validate the environment and CONFIG (which
#                                    may not exist yet); changes nothing
#   validator-role.sh apply CONFIG   check, then write the binding into CONFIG
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
  if [[ ! "$id" =~ ^[0-9A-Fa-f]{64}$ ]]; then
    refuse "VALIDATOR_ID must be exactly 64 hexadecimal digits (the controller account id)"
  fi
  id="${id,,}"
  if [[ "$id" =~ ^0{64}$ ]]; then
    refuse "VALIDATOR_ID is zero; it must name the controller account"
  fi
  printf '%s' "$id"
}

# The engine reads int256 config fields as base64 of the 32 bytes.
hex_to_base64() {
  local hex="$1" escaped="" i
  for ((i = 0; i < ${#hex}; i += 2)); do
    escaped+="\\x${hex:i:2}"
  done
  printf '%b' "$escaped" | base64 -w0
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
# configuration this script never inspected. Refused for every role. A
# single-dash word is refused when it contains D or c anywhere, because the
# engine accepts short options bundled into one word (-vD/other).
check_custom_arg_keeps_location() {
  local word
  for word in "${CUSTOM_WORDS[@]}"; do
    case "$word" in
      --db | --db=* | --local-config | --local-config=*)
        refuse "CUSTOM_ARG sets '$word'; the database and its configuration are fixed by the entrypoint"
        ;;
      --*) ;;
      -*[Dc]*)
        refuse "CUSTOM_ARG sets '$word'; the database and its configuration are fixed by the entrypoint"
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
  for ((i = 0; i < ${#CUSTOM_WORDS[@]}; i++)); do
    case "${CUSTOM_WORDS[i]}" in
      --json-rpc-address=*) value="${CUSTOM_WORDS[i]#--json-rpc-address=}" ;;
      --json-rpc-address)
        value="${CUSTOM_WORDS[i + 1]:-}"
        ;;
      *) continue ;;
    esac
    loopback_address "$value" ||
      refuse "CUSTOM_ARG binds JSON-RPC to '$value'; a validator may bind it to loopback only"
  done
}

check() {
  local config effective
  config="$1"
  custom_words
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
  [ -f "$config" ] || refuse "node config $config does not exist; initialize the node first"
  command -v jq >/dev/null || refuse "jq is required to edit $config"
  local id_b64 key_file existing
  id_b64="$(hex_to_base64 "$(normalized_validator_id)")"
  key_file="$PQ_CONSENSUS_KEY_FILE"
  existing="$(jq -c '.extraconfig.pq_consensus // empty' "$config")" ||
    refuse "cannot parse $config"
  if [ -n "$existing" ]; then
    local have_id have_file
    have_id="$(jq -r '.validator_id // ""' <<<"$existing")"
    have_file="$(jq -r '.consensus_key_file // ""' <<<"$existing")"
    if [ "$have_id" = "$id_b64" ] && [ "$have_file" = "$key_file" ]; then
      echo "[=] Validator binding already present in $config"
      return 0
    fi
    refuse "$config already binds validator $have_id with key $have_file; it is not rewritten from the environment. Edit it deliberately if the identity really changed"
  fi
  local tmp
  tmp="$(mktemp "$config.validator.XXXXXX")"
  # A missing state_serializer_enabled would be read as false and stop
  # persistent states (and with them garbage collection), so a new
  # extraconfig states the engine's default explicitly; an existing one
  # keeps its own fields.
  if ! jq --arg id "$id_b64" --arg file "$key_file" '
      .extraconfig = (
        (if (.extraconfig | type) == "object" then .extraconfig
         else {"@type": "engine.validator.extraConfig", "state_serializer_enabled": true} end)
        + {"pq_consensus": {"@type": "engine.validator.pqConsensus",
                            "validator_id": $id, "consensus_key_file": $file}})
    ' "$config" >"$tmp"; then
    rm -f -- "$tmp"
    refuse "cannot write the validator binding into $config"
  fi
  chmod --reference="$config" -- "$tmp"
  mv -- "$tmp" "$config"
  echo "[+] Wrote validator binding into $config"
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
