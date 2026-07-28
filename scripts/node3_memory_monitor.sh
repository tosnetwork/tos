#!/usr/bin/env bash
set -u

log_file=${1:-/tmp/tos-node3-memory.log}
max_seconds=${2:-28800}
start=$(date +%s)

while (( $(date +%s) - start < max_seconds )); do
  pid=$(pgrep -n -f '^/home/tomi/tos/build/validator-engine/validator-engine.*node3' || true)
  if [[ -z "$pid" || ! -r "/proc/$pid/status" ]]; then
    printf '%s process=not-running\n' "$(date -u +%FT%TZ)" >> "$log_file"
    exit 0
  fi
  rss=$(awk '/^VmRSS:/{print $2}' "/proc/$pid/status")
  anon=$(awk '/^RssAnon:/{print $2}' "/proc/$pid/status")
  file=$(awk '/^RssFile:/{print $2}' "/proc/$pid/status")
  swap=$(awk '/^VmSwap:/{print $2}' "/proc/$pid/status")
  printf '%s pid=%s rss_kb=%s anon_kb=%s file_kb=%s swap_kb=%s\n' \
    "$(date -u +%FT%TZ)" "$pid" "$rss" "$anon" "$file" "$swap" >> "$log_file"
  if (( rss >= 7340032 )); then
    printf '%s threshold=7GiB reached\n' "$(date -u +%FT%TZ)" >> "$log_file"
    exit 0
  fi
  sleep 60
done
