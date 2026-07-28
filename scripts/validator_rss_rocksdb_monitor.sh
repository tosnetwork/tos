#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "${script_dir}/.." && pwd)
service_name=${1:-${TOS_VALIDATOR_SERVICE:-}}
output_dir=${2:-${TOS_MEMORY_MONITOR_OUTPUT_DIR:-${repo_root}/var/validator-memory-monitor}}
summary_file=${output_dir}/rss-rocksdb-summary.csv
instances_file=${output_dir}/rocksdb-instances-v3.csv
write_buffer_manager_file=${output_dir}/write-buffer-manager.csv
unknown_paths_file=${output_dir}/unknown-rocksdb-paths.txt
lock_file=${output_dir}/monitor.lock

if [[ -z "$service_name" ]]; then
  echo "usage: $0 <validator-systemd-service> [output-directory]" >&2
  echo "or set TOS_VALIDATOR_SERVICE and optionally TOS_MEMORY_MONITOR_OUTPUT_DIR" >&2
  exit 2
fi

mkdir -p "$output_dir"
exec 9>"$lock_file"
flock -n 9 || exit 0

timestamp=$(date -u +%FT%TZ)
epoch=$(date +%s)
pid=$(systemctl show "$service_name" -p MainPID --value)

if [[ -z "$pid" || "$pid" == "0" || ! -r "/proc/$pid/status" ]]; then
  echo "$timestamp validator memory monitor: $service_name is not running" >&2
  exit 1
fi

if ! proc_status=$(<"/proc/$pid/status"); then
  echo "$timestamp validator memory monitor: $service_name restarted before /proc sampling; sample skipped" >&2
  exit 0
fi

proc_value() {
  local key=$1
  awk -v key="$key" '$1 == key ":" {print $2; found=1} END {if (!found) print 0}' <<<"$proc_status"
}

rss_kb=$(proc_value VmRSS)
anon_kb=$(proc_value RssAnon)
rss_file_kb=$(proc_value RssFile)
swap_kb=$(proc_value VmSwap)
uptime_sec=$(ps -p "$pid" -o etimes= 2>/dev/null | tr -d ' ' || true)

# A validator restart can race a timer invocation after MainPID was read but
# before /proc sampling completes. Do not append a misleading all-zero row for
# the exiting process; the next timer invocation will establish a new
# baseline.
current_pid=$(systemctl show "$service_name" -p MainPID --value)
if [[ "$current_pid" != "$pid" || "$rss_kb" == "0" || -z "$uptime_sec" ]]; then
  echo "$timestamp validator memory monitor: $service_name restarted during sampling; sample skipped" >&2
  exit 0
fi

cgroup_path=$(awk -F: '$1 == "0" {print $3}' "/proc/$pid/cgroup")
cgroup_stats=/sys/fs/cgroup${cgroup_path}/memory.stat
cgroup_current_file=/sys/fs/cgroup${cgroup_path}/memory.current
cgroup_current_bytes=0
cgroup_anon_bytes=0
cgroup_file_bytes=0
if [[ -r "$cgroup_current_file" ]]; then
  cgroup_current_bytes=$(<"$cgroup_current_file")
fi
if [[ -r "$cgroup_stats" ]]; then
  cgroup_anon_bytes=$(awk '$1 == "anon" {print $2}' "$cgroup_stats")
  cgroup_file_bytes=$(awk '$1 == "file" {print $2}' "$cgroup_stats")
fi

snapshot_file=$(mktemp "${output_dir}/rocksdb-snapshot.XXXXXX")
trap 'rm -f "$snapshot_file"' EXIT

# Each RocksDb instance emits diagnostics once per minute. A three-minute
# window tolerates timer jitter and actor scheduling delays while keeping the
# journal query cheap. The Perl map retains only the newest record per DB.
journalctl -u "$service_name" "_PID=$pid" --since "3 minutes ago" --no-pager -o cat \
  --grep='MEMORY_DIAGNOSTICS rocksdb' |
  perl -ne '
    if (/MEMORY_DIAGNOSTICS rocksdb db=(\S+).*?active_memtable_bytes=(\d+).*?all_memtable_reserved_bytes=(\d+).*?table_readers_bytes=(\d+).*?block_cache_bytes=(\d+)(.*)$/) {
      ($db, $active, $reserved, $readers, $cache, $suffix) = ($1, $2, $3, $4, $5, $6);
      ($manager, $mutable, $limit) = (0, 0, 0);
      ($domain, $flush_pending, $running_flushes, $pending_compaction, $delayed_rate, $write_stopped) =
        ("none", 0, 0, 0, 0, 0);
      if ($suffix =~ /write_buffer_manager_bytes=(\d+).*?write_buffer_manager_mutable_bytes=(\d+).*?write_buffer_manager_limit_bytes=(\d+)/) {
        ($manager, $mutable, $limit) = ($1, $2, $3);
      }
      if ($suffix =~ /write_buffer_manager_domain=(\w+)/) {
        $domain = $1;
      }
      if ($suffix =~ /memtable_flush_pending=(\d+)/) {
        $flush_pending = $1;
      }
      if ($suffix =~ /running_flushes=(\d+)/) {
        $running_flushes = $1;
      }
      if ($suffix =~ /pending_compaction_bytes=(\d+)/) {
        $pending_compaction = $1;
      }
      if ($suffix =~ /actual_delayed_write_rate=(\d+)/) {
        $delayed_rate = $1;
      }
      if ($suffix =~ /write_stopped=(\d+)/) {
        $write_stopped = $1;
      }
      $row{$db} = [
        $active, $reserved, $readers, $cache, $manager, $mutable, $limit,
        $domain, $flush_pending, $running_flushes, $pending_compaction,
        $delayed_rate, $write_stopped
      ];
    }
    END {
      for $db (sort keys %row) {
        print join(",", $db, @{$row{$db}}), "\n";
      }
    }
  ' >"$snapshot_file"

rocksdb_count=$(wc -l <"$snapshot_file")
if ((rocksdb_count == 0)); then
  if ((uptime_sec < 180)); then
    echo "$timestamp validator memory monitor: RocksDB diagnostics are not available during startup; sample skipped" >&2
    exit 0
  fi
  echo "$timestamp validator memory monitor: no RocksDB diagnostics found in the last three minutes" >&2
  exit 1
fi

# Keep the classifier honest as new validator databases are introduced. Warn
# once for each previously unseen path instead of silently folding it into the
# "other" aggregate forever. The state file also makes the warning auditable
# across timer invocations.
while IFS=, read -r db_path _; do
  case "$db_path" in
    ./celldb/ | ./state/ | ./wc0-index | ./overlays | ./dht-* | ./catchainreceiver* | ./consensus/* | \
      ./archive/* | ./files/globalindex | ./files/packages/temp.archive.* | ./packed/globalindex)
      continue
      ;;
  esac
  if [[ ! -f "$unknown_paths_file" ]] || ! grep -Fqx -- "$db_path" "$unknown_paths_file"; then
    echo "$timestamp validator memory monitor: unrecognized RocksDB path: $db_path" >&2
    printf '%s\n' "$db_path" >>"$unknown_paths_file"
  fi
done <"$snapshot_file"

if [[ ! -s "$instances_file" ]]; then
  printf '%s\n' \
    'timestamp_utc,epoch,db,active_memtable_bytes,reserved_memtable_bytes,table_readers_bytes,block_cache_bytes,write_buffer_manager_bytes,write_buffer_manager_mutable_bytes,write_buffer_manager_limit_bytes,write_buffer_manager_domain,memtable_flush_pending,running_flushes,pending_compaction_bytes,actual_delayed_write_rate,write_stopped' \
    >"$instances_file"
fi
awk -v timestamp="$timestamp" -v epoch="$epoch" \
  '{print timestamp "," epoch "," $0}' "$snapshot_file" >>"$instances_file"

read -r write_buffer_manager_bytes write_buffer_manager_mutable_bytes \
  write_buffer_manager_limit_bytes < <(
  awk -F, '
    {
      domain=$9
      if (domain == "critical" || domain == "global") {
        if ($6 > manager[domain]) manager[domain]=$6
        if ($7 > mutable[domain]) mutable[domain]=$7
        if ($8 > limit[domain]) limit[domain]=$8
      } else if (domain == "explicit") {
        # Explicit managers have no stable identifier in the log. Validator
        # production paths do not use them; retain the largest observation
        # without double-counting the repeated per-DB process managers.
        if ($6 > explicit_manager) explicit_manager=$6
        if ($7 > explicit_mutable) explicit_mutable=$7
        if ($8 > explicit_limit) explicit_limit=$8
      }
    }
    END {
      printf "%.0f %.0f %.0f\n",
        manager["critical"] + manager["global"] + explicit_manager,
        mutable["critical"] + mutable["global"] + explicit_mutable,
        limit["critical"] + limit["global"] + explicit_limit
    }
  ' "$snapshot_file"
)
if [[ ! -s "$write_buffer_manager_file" ]]; then
  printf '%s\n' \
    'timestamp_utc,epoch,pid,uptime_sec,write_buffer_manager_bytes,write_buffer_manager_mutable_bytes,write_buffer_manager_limit_bytes' \
    >"$write_buffer_manager_file"
fi
printf '%s\n' \
  "$timestamp,$epoch,$pid,$uptime_sec,$write_buffer_manager_bytes,$write_buffer_manager_mutable_bytes,$write_buffer_manager_limit_bytes" \
  >>"$write_buffer_manager_file"

read -r rocksdb_active_bytes rocksdb_reserved_bytes rocksdb_table_readers_bytes \
  shared_block_cache_bytes celldb_block_cache_bytes \
  celldb_active_bytes celldb_reserved_bytes \
  consensus_active_bytes consensus_reserved_bytes \
  archive_active_bytes archive_reserved_bytes \
  other_active_bytes other_reserved_bytes < <(
  awk -F, '
    {
      db=$1
      active=$2
      reserved=$3
      readers=$4
      cache=$5
      active_total+=active
      reserved_total+=reserved
      readers_total+=readers

      if (db == "./celldb/") {
        celldb_cache=cache
        celldb_active+=active
        celldb_reserved+=reserved
      } else {
        if (cache > shared_cache) {
          shared_cache=cache
        }
        if (db ~ /^\.\/consensus\//) {
          consensus_active+=active
          consensus_reserved+=reserved
        } else if (db ~ /^\.\/archive\// || db ~ /^\.\/files\/packages\/temp\.archive\./) {
          archive_active+=active
          archive_reserved+=reserved
        } else {
          other_active+=active
          other_reserved+=reserved
        }
      }
    }
    END {
      printf "%.0f %.0f %.0f %.0f %.0f %.0f %.0f %.0f %.0f %.0f %.0f %.0f %.0f\n",
        active_total, reserved_total, readers_total, shared_cache, celldb_cache,
        celldb_active, celldb_reserved, consensus_active, consensus_reserved,
        archive_active, archive_reserved, other_active, other_reserved
    }
  ' "$snapshot_file"
)

read -r flush_pending_databases running_flushes pending_compaction_bytes \
  delayed_write_databases write_stopped_databases < <(
  awk -F, '
    {
      flush_pending+=($10 != 0)
      running_flushes+=$11
      pending_compaction+=$12
      delayed+=($13 != 0)
      stopped+=($14 != 0)
    }
    END {
      printf "%.0f %.0f %.0f %.0f %.0f\n",
        flush_pending, running_flushes, pending_compaction, delayed, stopped
    }
  ' "$snapshot_file"
)

header='timestamp_utc,epoch,pid,uptime_sec,rss_kb,anon_kb,rss_file_kb,swap_kb,cgroup_current_bytes,cgroup_anon_bytes,cgroup_file_bytes,rocksdb_count,rocksdb_active_bytes,rocksdb_reserved_bytes,rocksdb_table_readers_bytes,shared_block_cache_bytes,celldb_block_cache_bytes,celldb_active_bytes,celldb_reserved_bytes,consensus_active_bytes,consensus_reserved_bytes,archive_active_bytes,archive_reserved_bytes,other_active_bytes,other_reserved_bytes,window_seconds,rss_delta_kb,active_memtable_delta_bytes,reserved_memtable_delta_bytes,rss_rate_mib_per_min,reserved_memtable_rate_mib_per_min,memtable_explanation_ratio,status,flush_pending_databases,running_flushes,pending_compaction_bytes,delayed_write_databases,write_stopped_databases'
if [[ ! -s "$summary_file" ]]; then
  printf '%s\n' "$header" >"$summary_file"
fi

# Prefer a ten-minute comparison. During the first ten minutes, compare with
# the oldest available sample so that the monitor starts producing useful
# output immediately.
previous=$(
  awk -F, -v target=$((epoch - 600)) '
    NR == 1 {next}
    NR == 2 {oldest=$0}
    $2 <= target {candidate=$0}
    END {
      if (candidate != "") {
        print candidate
      } else {
        print oldest
      }
    }
  ' "$summary_file"
)

window_seconds=0
rss_delta_kb=0
active_memtable_delta_bytes=0
reserved_memtable_delta_bytes=0
rss_rate_mib_per_min=0
reserved_memtable_rate_mib_per_min=0
memtable_explanation_ratio=0
status=collecting_baseline

if [[ -n "$previous" ]]; then
  read -r previous_epoch previous_pid previous_rss_kb previous_active_bytes previous_reserved_bytes < <(
    awk -F, '{print $2, $3, $5, $13, $14}' <<<"$previous"
  )
  if [[ "$previous_pid" != "$pid" ]]; then
    status=process_restarted_collecting_baseline
  else
    window_seconds=$((epoch - previous_epoch))
    rss_delta_kb=$((rss_kb - previous_rss_kb))
    active_memtable_delta_bytes=$((rocksdb_active_bytes - previous_active_bytes))
    reserved_memtable_delta_bytes=$((rocksdb_reserved_bytes - previous_reserved_bytes))

    read -r rss_rate_mib_per_min reserved_memtable_rate_mib_per_min \
      memtable_explanation_ratio status < <(
      awk -v seconds="$window_seconds" \
        -v rss_delta_kb="$rss_delta_kb" \
        -v active_delta="$active_memtable_delta_bytes" \
        -v reserved_delta="$reserved_memtable_delta_bytes" '
        BEGIN {
          if (seconds <= 0) {
            print "0 0 0 invalid_window"
            exit
          }

          rss_rate=(rss_delta_kb / 1024.0) / (seconds / 60.0)
          reserved_rate=(reserved_delta / 1048576.0) / (seconds / 60.0)
          ratio=0
          if (rss_delta_kb > 0 && reserved_delta > 0) {
            ratio=reserved_delta / (rss_delta_kb * 1024.0)
          }

          if (seconds < 300) {
            state="warming_sample_window"
          } else if (rss_rate <= 0.5) {
            state="rss_stable_or_decreasing"
          } else if (reserved_delta > 0 && ratio >= 0.60) {
            state="rocksdb_memtable_dominant"
          } else if (active_delta < 0 && reserved_delta >= 0) {
            state="rocksdb_flush_history_retained"
          } else if (reserved_delta > 0 && ratio >= 0.30) {
            state="rocksdb_memtable_contributor"
          } else {
            state="rss_growth_not_explained_by_memtables"
          }

          printf "%.3f %.3f %.3f %s\n", rss_rate, reserved_rate, ratio, state
        }
      '
    )
  fi
fi

printf '%s\n' \
  "$timestamp,$epoch,$pid,$uptime_sec,$rss_kb,$anon_kb,$rss_file_kb,$swap_kb,$cgroup_current_bytes,$cgroup_anon_bytes,$cgroup_file_bytes,$rocksdb_count,$rocksdb_active_bytes,$rocksdb_reserved_bytes,$rocksdb_table_readers_bytes,$shared_block_cache_bytes,$celldb_block_cache_bytes,$celldb_active_bytes,$celldb_reserved_bytes,$consensus_active_bytes,$consensus_reserved_bytes,$archive_active_bytes,$archive_reserved_bytes,$other_active_bytes,$other_reserved_bytes,$window_seconds,$rss_delta_kb,$active_memtable_delta_bytes,$reserved_memtable_delta_bytes,$rss_rate_mib_per_min,$reserved_memtable_rate_mib_per_min,$memtable_explanation_ratio,$status,$flush_pending_databases,$running_flushes,$pending_compaction_bytes,$delayed_write_databases,$write_stopped_databases" \
  >>"$summary_file"

echo "$timestamp validator memory monitor: service=$service_name rss_mib=$(awk -v kb="$rss_kb" 'BEGIN {printf "%.1f", kb/1024}') active_memtable_mib=$(awk -v bytes="$rocksdb_active_bytes" 'BEGIN {printf "%.1f", bytes/1048576}') retained_memtable_mib=$(awk -v bytes="$rocksdb_reserved_bytes" 'BEGIN {printf "%.1f", bytes/1048576}') write_buffer_manager_mib=$(awk -v bytes="$write_buffer_manager_bytes" 'BEGIN {printf "%.1f", bytes/1048576}') write_buffer_manager_mutable_mib=$(awk -v bytes="$write_buffer_manager_mutable_bytes" 'BEGIN {printf "%.1f", bytes/1048576}') write_buffer_manager_limit_mib=$(awk -v bytes="$write_buffer_manager_limit_bytes" 'BEGIN {printf "%.1f", bytes/1048576}') flush_pending_databases=$flush_pending_databases running_flushes=$running_flushes pending_compaction_mib=$(awk -v bytes="$pending_compaction_bytes" 'BEGIN {printf "%.1f", bytes/1048576}') delayed_write_databases=$delayed_write_databases write_stopped_databases=$write_stopped_databases window_seconds=$window_seconds rss_rate_mib_per_min=$rss_rate_mib_per_min memtable_rate_mib_per_min=$reserved_memtable_rate_mib_per_min explanation_ratio=$memtable_explanation_ratio status=$status"
