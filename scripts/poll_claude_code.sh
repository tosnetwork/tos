#!/usr/bin/env bash
set -u

claude_pid=${1:?claude pid required}
log_file=${2:-/tmp/tos-claude-code-poll.log}
deadline=$(( $(date +%s) + ${3:-28800} ))

while (( $(date +%s) < deadline )); do
  if kill -0 "$claude_pid" 2>/dev/null; then
    printf '%s claude_pid=%s status=running\n' "$(date -u +%FT%TZ)" "$claude_pid" >> "$log_file"
    sleep 30
    continue
  fi
  printf '%s claude_pid=%s status=finished\n' "$(date -u +%FT%TZ)" "$claude_pid" >> "$log_file"
  git -C /home/tomi/tos status --short >> "$log_file" 2>&1 || true
  git -C /home/tomi/tos diff --stat >> "$log_file" 2>&1 || true
  exit 0
done
printf '%s claude_pid=%s status=monitor-timeout\n' "$(date -u +%FT%TZ)" "$claude_pid" >> "$log_file"
