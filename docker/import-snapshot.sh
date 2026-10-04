#!/usr/bin/env bash
# Import a database snapshot into a new node, or refuse.
#
# A snapshot replaces the chain state the node would otherwise verify for
# itself, so its content must be authenticated by something the operator
# controls. TLS on the download only says which server answered; a checksum
# fetched from the same place as the archive says nothing more. The archive is
# therefore accepted only when its SHA-256 equals DUMP_SHA256, a digest the
# operator puts in the node's own configuration. That digest is the only trust
# anchor here, and it authenticates the archive only if the operator obtained
# it independently of the snapshot download.
#
# DUMP_ZEROSTATE_ROOT_HASH must equal the zero state in the node's global
# config. That is a consistency check between two operator settings: it stops
# a digest meant for one network being used on a node configured for another.
# It does not authenticate the global config, which is trusted as configured.
#
# The database must be new: before anything is installed it may hold only the
# node's own configuration and keys (config.json, keyring/, tos-global.config)
# and an empty lost+found. A snapshot is never merged into existing chain data.
#
# Environment (all set by the operator):
#   SNAPSHOT_IMPORT            "1" or "true" to import. Import is off by default.
#   DUMP_URL                   https:// (or file://) location of the .tar.lz archive.
#   DUMP_SHA256                SHA-256 of the archive file, 64 hex characters.
#   DUMP_ZEROSTATE_ROOT_HASH   validator.zero_state.root_hash of the network the
#                              snapshot belongs to; must equal the node's global
#                              config (a consistency check, not authentication).
#   SNAPSHOT_STAGING_DIR       where the archive is downloaded and unpacked;
#                              must be outside the database directory. Put it on
#                              the database volume's filesystem so the final
#                              moves are renames.
#   TOS_DB_DIR                 database directory (default /var/tos-work/db).
#   TOS_GLOBAL_CONFIG          global config (default $TOS_DB_DIR/tos-global.config).
#
# Exit status: 0 when the snapshot was imported or had already been imported,
# or when import is not requested; non-zero on any refusal or failure. Nothing
# is written into the database directory until the archive has been verified,
# listed, unpacked and checked in staging, and the success marker is written
# last.

set -euo pipefail

DB_DIR="${TOS_DB_DIR:-/var/tos-work/db}"
GLOBAL_CONFIG="${TOS_GLOBAL_CONFIG:-$DB_DIR/tos-global.config}"
STAGING_DIR="${SNAPSHOT_STAGING_DIR:-/var/tos-work/snapshot-staging}"
MARKER="$DB_DIR/.snapshot-imported"
LEGACY_MARKER="$DB_DIR/dump_downloaded"

# What a new database may already hold before the import: the node's own
# identity and configuration written by validator-engine and init.sh, and the
# lost+found a freshly formatted volume carries at its root.
NEW_DB_ENTRIES=(config.json keyring tos-global.config lost+found)
# Top-level names an archive may not carry: everything a new database may
# already hold, and this script's bookkeeping.
RESERVED_TOP_LEVEL=("${NEW_DB_ENTRIES[@]}" .snapshot-imported .snapshot-imported.tmp dump_downloaded)

fail() {
  echo "[snapshot] refused: $*" >&2
  exit 1
}

log() {
  echo "[snapshot] $*"
}

is_reserved() {
  local candidate="$1" reserved
  for reserved in "${RESERVED_TOP_LEVEL[@]}"; do
    [ "$candidate" != "$reserved" ] || return 0
  done
  return 1
}

# Refuse unless the database holds nothing but NEW_DB_ENTRIES, each of the
# expected kind. Runs before the download and again immediately before the
# install, so content that appears while the archive is staged is not merged.
require_new_database() {
  local entry name
  while IFS= read -r -d '' entry; do
    name="${entry##*/}"
    case "$name" in
      config.json | tos-global.config)
        [ -f "$entry" ] && [ ! -L "$entry" ] ||
          fail "database entry $name is not a regular file; import only into a new database"
        ;;
      keyring)
        [ -d "$entry" ] && [ ! -L "$entry" ] ||
          fail "database entry keyring is not a directory; import only into a new database"
        ;;
      lost+found)
        [ -d "$entry" ] && [ ! -L "$entry" ] && [ -z "$(ls -A -- "$entry" 2>/dev/null || echo unreadable)" ] ||
          fail "database entry lost+found is not an empty directory; import only into a new database"
        ;;
      *)
        fail "the database directory is not new: it contains $name; a snapshot is imported only into a database holding nothing but ${NEW_DB_ENTRIES[*]}"
        ;;
    esac
  done < <(find "$DB_DIR" -mindepth 1 -maxdepth 1 -print0)
}

import_requested() {
  case "${SNAPSHOT_IMPORT:-}" in
    1 | true) return 0 ;;
    "" | 0 | false) return 1 ;;
    *) fail "SNAPSHOT_IMPORT must be 1, true, 0 or false, not '${SNAPSHOT_IMPORT}'" ;;
  esac
}

if ! import_requested; then
  if [ -n "${DUMP_URL:-}" ]; then
    fail "DUMP_URL is set but SNAPSHOT_IMPORT is not enabled; set SNAPSHOT_IMPORT=1 together with DUMP_SHA256 and DUMP_ZEROSTATE_ROOT_HASH, or unset DUMP_URL"
  fi
  exit 0
fi

# ---- Configuration: everything checked before any network or disk access.

[ -n "${DUMP_URL:-}" ] || fail "SNAPSHOT_IMPORT is enabled but DUMP_URL is empty"
case "$DUMP_URL" in
  https://* | file://*) ;;
  *) fail "DUMP_URL must be an https:// or file:// URL" ;;
esac

digest="${DUMP_SHA256:-}"
digest="${digest,,}"
[[ "$digest" =~ ^[0-9a-f]{64}$ ]] || fail "DUMP_SHA256 must be the archive's SHA-256 as 64 hex characters"

expected_zerostate="${DUMP_ZEROSTATE_ROOT_HASH:-}"
[ -n "$expected_zerostate" ] || fail "DUMP_ZEROSTATE_ROOT_HASH must name the network the snapshot belongs to"
[ -f "$GLOBAL_CONFIG" ] || fail "global config $GLOBAL_CONFIG is missing"
configured_zerostate="$(jq -er '.validator.zero_state.root_hash' "$GLOBAL_CONFIG")" ||
  fail "cannot read validator.zero_state.root_hash from $GLOBAL_CONFIG"
[ "$configured_zerostate" = "$expected_zerostate" ] ||
  fail "DUMP_ZEROSTATE_ROOT_HASH $expected_zerostate does not match zero state $configured_zerostate in $GLOBAL_CONFIG (a consistency check between operator settings; it authenticates neither)"

[ -d "$DB_DIR" ] || fail "database directory $DB_DIR is missing"
db_real="$(realpath -e "$DB_DIR")"
staging_real="$(realpath -m "$STAGING_DIR")"
case "$staging_real/" in
  "$db_real"/*) fail "SNAPSHOT_STAGING_DIR $staging_real is inside the database directory $db_real" ;;
esac
case "$db_real/" in
  "$staging_real"/*) fail "the database directory $db_real is inside SNAPSHOT_STAGING_DIR $staging_real" ;;
esac

if [ -f "$MARKER" ]; then
  recorded="$(cat "$MARKER")"
  if [ "$recorded" != "$digest" ]; then
    fail "the database already holds snapshot $recorded; refusing to import $digest over it"
  fi
  log "snapshot $digest already imported"
  exit 0
fi
if [ -e "$LEGACY_MARKER" ]; then
  fail "the database holds an earlier unverified snapshot import ($LEGACY_MARKER); start from an empty database to import a verified one"
fi
require_new_database

# ---- Staging: download, verify, list, unpack. The database is not touched.

mkdir -p -- "$staging_real"
work="$(mktemp -d "$staging_real/import.XXXXXXXX")"
cleanup() {
  rm -rf -- "$work"
}
trap cleanup EXIT

archive="$work/snapshot.tar.lz"
extract="$work/extract"
mkdir "$extract"

log "downloading $DUMP_URL"
curl --fail --silent --show-error --location --proto '=https,file' --proto-redir '=https' \
  --retry 10 --retry-delay 30 --output "$archive" "$DUMP_URL" ||
  fail "download failed"

actual="$(sha256sum "$archive" | cut -d' ' -f1)"
[ "$actual" = "$digest" ] || fail "archive SHA-256 $actual does not match DUMP_SHA256 $digest"
log "archive matches the operator-supplied DUMP_SHA256; this authenticates it only if that digest was obtained independently of the download"

# Member policy, checked on the listing before anything is unpacked: only
# regular files and directories, relative names without '..', and no
# reserved top-level name. Every component is normalized the way tar resolves
# it on extraction ('' and '.' vanish), so './././keyring' and './/keyring'
# are both 'keyring'. This check keeps hostile members out of staging; the
# check of the unpacked tree below is the one the install relies on.
listing="$work/listing"
plzip -d -c "$archive" | tar --list --verbose --numeric-owner --quoting-style=escape --file - >"$listing" ||
  fail "archive cannot be decompressed and listed"
[ -s "$listing" ] || fail "archive is empty"

while IFS= read -r line; do
  type="${line:0:1}"
  case "$type" in
    - | d) ;;
    *) fail "archive member is neither a regular file nor a directory: $line" ;;
  esac
  read -r _perms _owner _size _date _time name <<<"$line"
  case "$name" in
    /*) fail "archive member has an absolute name: $name" ;;
  esac
  IFS='/' read -r -a parts <<<"$name"
  top=""
  for part in "${parts[@]}"; do
    case "$part" in
      .) continue ;;
      ..) fail "archive member escapes its directory: $name" ;;
    esac
    # An empty component (from '//' or a trailing '/') never becomes the top.
    [ -n "$top" ] || top="$part"
  done
  if [ -n "$top" ] && is_reserved "$top"; then
    fail "archive member overwrites the node's own $top: $name"
  fi
done <"$listing"

plzip -d -c "$archive" | tar --extract --file - --directory "$extract" \
  --no-same-owner --no-same-permissions --no-overwrite-dir ||
  fail "archive cannot be unpacked"

# The unpacked tree is what gets installed, so it is checked again directly,
# independently of how the listing above was parsed: real top-level names, and
# nothing but regular, singly linked files and directories anywhere.
mapfile -d '' entries < <(find "$extract" -mindepth 1 -maxdepth 1 -print0)
[ "${#entries[@]}" -gt 0 ] || fail "archive unpacked to nothing"
for entry in "${entries[@]}"; do
  name="${entry##*/}"
  if is_reserved "$name"; then
    fail "unpacked archive carries the node's own $name"
  fi
done
odd="$(find "$extract" -mindepth 1 ! -type f ! -type d -print -quit)"
[ -z "$odd" ] || fail "unpacked archive contains something that is neither a regular file nor a directory: ${odd#"$extract"/}"
linked="$(find "$extract" -type f -links +1 -print -quit)"
[ -z "$linked" ] || fail "unpacked archive contains a hard-linked file: ${linked#"$extract"/}"

# ---- Install: move verified entries into place, then write the marker.

require_new_database
for entry in "${entries[@]}"; do
  mv -T -- "$entry" "$DB_DIR/${entry##*/}" || fail "cannot move ${entry##*/} into the database"
done
printf '%s' "$digest" >"$MARKER.tmp"
mv -f -- "$MARKER.tmp" "$MARKER"
log "imported snapshot $digest"
