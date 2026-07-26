#!/usr/bin/env bash
set -euo pipefail

# Read-only validator memory audit.  It classifies RSS from smaps and records
# anonymous mmap ranges, file-backed mappings, deleted mappings, and huge pages.
# Usage: validator_memory_audit.sh <pid> [interval_seconds] [output_dir]

pid=${1:?pid is required}
interval=${2:-10}
out=${3:-/tmp/tos-memory-audit-$pid}
mkdir -p "$out"

while [[ -d "/proc/$pid" ]]; do
  ts=$(date -u +%Y%m%dT%H%M%SZ)
  rollup="$out/${ts}.smaps_rollup"
  maps="$out/${ts}.maps_summary"
  cat "/proc/$pid/smaps_rollup" > "$rollup"

  awk '
    function flush() {
      if (!hdr) return
      kind = "anonymous"
      if (path != "" && path !~ /^\[.*\]$/) kind = (path ~ / \(deleted\)$/ ? "deleted-file" : "file-backed")
      else if (path ~ /^\[heap\]$/) kind = "heap"
      else if (path ~ /^\[stack/) kind = "stack"
      rss[kind] += r; pss[kind] += p; anon[kind] += a; swap[kind] += s
      count[kind]++
      hdr = 0; r = p = a = s = 0; path = ""
    }
    /^[0-9a-f]+-[0-9a-f]+ / {
      flush(); hdr=1
      # Anonymous mappings have only five header fields and end in "00:00 0".
      # For file-backed mappings preserve the pathname, including spaces.
      path = (NF >= 6 ? substr($0, index($0, $6)) : "")
      next
    }
    /^Rss:/ { r += $2; next }
    /^Pss:/ { p += $2; next }
    /^Anonymous:/ { a += $2; next }
    /^Swap:/ { s += $2; next }
    END { flush(); for (k in rss) printf "%s mappings=%d rss_kb=%d pss_kb=%d anonymous_kb=%d swap_kb=%d\n", k,count[k],rss[k],pss[k],anon[k],swap[k] }
  ' "/proc/$pid/smaps" | sort > "$maps"

  {
    echo "timestamp=$ts pid=$pid"
    grep -E '^(Rss|Pss|Private_Dirty|Anonymous|AnonHugePages|FilePmdMapped|Shared_Hugetlb|Swap):' "$rollup" || true
    echo "--- mapping classes"
    cat "$maps"
    echo "--- largest mappings"
    awk '/^[0-9a-f]+-[0-9a-f]+ /{h=$0; r=0} /^Rss:/{r=$2; print r, h}' /proc/$pid/smaps | sort -nr | head -n 20
  } > "$out/${ts}.report"
  sleep "$interval"
done
