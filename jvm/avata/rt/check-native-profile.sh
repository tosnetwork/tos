#!/bin/sh
set -eu

root=${1:-.}

forbidden_native_pattern='Avata_sun_misc_Unsafe_|Avata_java_internal_Machine_|Avata_java_internal_avatavmresource_|Avata_java_internal_SystemClassSpace_(resourceURLPrefix|.*ResourceEnumeration)|Avata_java_io_ObjectInputStream_makeInstance|Avata_java_internal_LegacyObjectInputStream_makeInstance|Java_java_io_(File|FileInputStream|FileOutputStream|RandomAccessFile)|Java_java_lang_Runtime_|Java_java_lang_System_(getNativeProperties|getEnvironment|currentTimeMillis|doMapLibraryName)|Java_java_util_Date_toString'

bad_entries=$(
  find "$root/src" "$root/rt" -type f \
    \( -name '*.c' -o -name '*.cc' -o -name '*.cpp' -o -name '*.h' \) \
    -print \
    | xargs grep -nE "$forbidden_native_pattern" 2>/dev/null || true
)

if [ -n "$bad_entries" ]; then
  echo "native profile check failed: stale host native entry points remain:" >&2
  echo "$bad_entries" >&2
  exit 1
fi

echo "native profile check: success"
