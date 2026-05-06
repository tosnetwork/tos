#!/bin/sh
set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
  echo "usage: $0 <rt.jar> [jar-command]" >&2
  exit 2
fi

rt_jar=$1
jar_cmd=${2:-jar}

if [ ! -f "$rt_jar" ]; then
  echo "rt profile check failed: missing $rt_jar" >&2
  exit 2
fi

bad_entries=$("$jar_cmd" tf "$rt_jar" | awk '
function reject(reason) {
  print $0 " (" reason ")";
  failed = 1;
}

/\/$/ {
  next;
}

$0 ~ /^META-INF\// {
  next;
}

$0 ~ /^java\/net\// { reject("forbidden java.net package"); next; }
$0 ~ /^java\/nio\// { reject("forbidden java.nio package"); next; }
$0 ~ /^java\/security\// { reject("forbidden java.security package"); next; }
$0 ~ /^java\/text\// { reject("forbidden java.text package"); next; }
$0 ~ /^java\/math\// { reject("forbidden java.math package"); next; }
$0 ~ /^java\/util\/concurrent\// { reject("forbidden java.util.concurrent package"); next; }
$0 ~ /^java\/util\/logging\// { reject("forbidden java.util.logging package"); next; }
$0 ~ /^java\/util\/regex\// { reject("forbidden java.util.regex package"); next; }
$0 ~ /^java\/util\/zip\// { reject("forbidden java.util.zip package"); next; }
$0 ~ /^java\/util\/jar\// { reject("forbidden java.util.jar package"); next; }
$0 ~ /^javax\// { reject("forbidden javax package"); next; }
$0 == "java/lang/Process.class" { reject("forbidden process API"); next; }
$0 == "java/lang/ProcessBuilder.class" { reject("forbidden process API"); next; }
$0 == "sun/misc/Unsafe.class" { reject("forbidden unsafe API"); next; }
$0 == "avata/Machine.class" { reject("forbidden host VM API"); next; }
$0 == "avata/Traces.class" { reject("forbidden host tracing API"); next; }
$0 == "java/lang/invoke/MutableCallSite.class" { reject("forbidden mutable call site"); next; }
$0 == "java/lang/invoke/VolatileCallSite.class" { reject("forbidden volatile call site"); next; }
$0 == "java/lang/invoke/SerializedLambda.class" { reject("forbidden lambda serialization"); next; }
$0 == "java/lang/invoke/MethodHandleInfo.class" { reject("forbidden method-handle introspection"); next; }

$0 ~ /^sun\// && $0 != "sun/misc/Cleaner.class" && $0 != "sun/reflect/ConstantPool.class" {
  reject("unexpected sun internal class");
  next;
}

$0 ~ /^avata\// { next; }
$0 ~ /^java\/lang\// { next; }
$0 ~ /^java\/io\// { next; }
$0 ~ /^java\/util\// { next; }
$0 == "sun/misc/Cleaner.class" { next; }
$0 == "sun/reflect/ConstantPool.class" { next; }

{
  reject("outside admitted rt.jar package roots");
}

END {
  exit failed ? 1 : 0;
}
' || true)

if [ -n "$bad_entries" ]; then
  echo "rt profile check failed for $rt_jar:" >&2
  echo "$bad_entries" >&2
  exit 1
fi

echo "rt profile check: success"
