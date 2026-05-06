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
$0 == "java/io/FileDescriptor.class" { reject("forbidden host file descriptor API"); next; }
$0 == "java/io/FileInputStream.class" { reject("forbidden host file descriptor API"); next; }
$0 == "java/io/FileOutputStream.class" { reject("forbidden host file descriptor API"); next; }
$0 == "java/io/FileNotFoundException.class" { reject("forbidden host file API"); next; }
$0 == "java/io/FilterReader.class" { reject("forbidden reader decorator API"); next; }
$0 == "java/io/LineNumberReader.class" { reject("forbidden source-position reader API"); next; }
$0 == "java/io/PushbackReader.class" { reject("forbidden parser pushback reader API"); next; }
$0 == "java/lang/Process.class" { reject("forbidden process API"); next; }
$0 == "java/lang/ProcessBuilder.class" { reject("forbidden process API"); next; }
$0 == "java/lang/Runtime.class" { reject("forbidden host runtime API"); next; }
$0 == "java/lang/IllegalThreadStateException.class" { reject("forbidden thread scheduling API"); next; }
$0 == "java/lang/IllegalAccessException.class" { reject("forbidden reflection exception API"); next; }
$0 == "java/lang/SecurityException.class" { reject("forbidden security-manager API"); next; }
$0 == "java/lang/StringBuffer.class" { reject("forbidden legacy synchronized string buffer"); next; }
$0 == "java/lang/ClassLoader.class" { reject("forbidden dynamic class-loader API"); next; }
$0 == "java/lang/Thread.class" { reject("forbidden thread API"); next; }
$0 == "java/lang/ThreadDeath.class" { reject("forbidden thread scheduling API"); next; }
$0 == "java/lang/ThreadGroup.class" { reject("forbidden thread API"); next; }
$0 == "java/lang/ThreadLocal.class" { reject("forbidden thread-local API"); next; }
$0 == "java/lang/TypeNotPresentException.class" { reject("forbidden optional reflective type API"); next; }
$0 == "java/lang/InheritableThreadLocal.class" { reject("forbidden thread-local API"); next; }
$0 == "java/lang/Class$ClassType.class" { reject("forbidden reflection classification helper"); next; }
$0 == "java/lang/NoSuchFieldException.class" { reject("forbidden reflection exception API"); next; }
$0 == "java/lang/NoSuchMethodException.class" { reject("forbidden reflection exception API"); next; }
$0 == "java/lang/Package.class" { reject("forbidden package metadata API"); next; }
$0 == "sun/misc/Unsafe.class" { reject("forbidden unsafe API"); next; }
$0 == "avata/Machine.class" { reject("forbidden host VM API"); next; }
$0 == "avata/Traces.class" { reject("forbidden host tracing API"); next; }
$0 == "avata/VMClassLoader.class" { reject("stale VM class-loader shell"); next; }
$0 == "avata/SystemClassLoader.class" { reject("stale VM class-loader shell"); next; }
$0 == "avata/VMThread.class" { reject("stale VM thread shell"); next; }
$0 == "avata/VMThreadGroup.class" { reject("stale VM thread-group shell"); next; }
$0 == "avata/Assembler.class" { reject("forbidden class-file generation helper"); next; }
$0 ~ /^avata\/Assembler\$/ { reject("forbidden class-file generation helper"); next; }
$0 == "avata/ConstantPool.class" { reject("forbidden class-file generation helper"); next; }
$0 ~ /^avata\/ConstantPool\$/ { reject("forbidden class-file generation helper"); next; }
$0 == "avata/Stream.class" { reject("forbidden binary class-file stream helper"); next; }
$0 == "avata/Callback.class" { reject("forbidden continuation API"); next; }
$0 == "avata/Function.class" { reject("forbidden continuation API"); next; }
$0 == "avata/Continuations.class" { reject("forbidden continuation API"); next; }
$0 ~ /^avata\/Continuations\$/ { reject("forbidden continuation API"); next; }
$0 == "avata/IncompatibleContinuationException.class" { reject("forbidden continuation API"); next; }
$0 == "java/util/HashMap.class" { reject("forbidden hash collection"); next; }
$0 == "java/util/HashSet.class" { reject("forbidden hash collection"); next; }
$0 == "java/util/Hashtable.class" { reject("forbidden hash collection"); next; }
$0 == "java/util/EnumSet.class" { reject("forbidden enum collection"); next; }
$0 == "java/util/AbstractMap.class" { reject("forbidden empty map shell"); next; }
$0 == "java/util/IdentityHashMap.class" { reject("forbidden identity hash collection"); next; }
$0 == "java/util/LinkedHashMap.class" { reject("forbidden hash collection"); next; }
$0 == "java/util/LinkedHashSet.class" { reject("forbidden hash collection"); next; }
$0 == "java/util/NavigableMap.class" { reject("forbidden partial navigable map API"); next; }
$0 == "java/util/Properties.class" { reject("forbidden mutable host-property map"); next; }
$0 == "java/util/WeakHashMap.class" { reject("forbidden weak hash collection"); next; }
$0 == "java/util/Enumeration.class" { reject("forbidden legacy iterator API"); next; }
$0 == "java/util/Vector.class" { reject("forbidden legacy synchronized collection"); next; }
$0 == "java/util/Stack.class" { reject("forbidden legacy synchronized collection"); next; }
$0 == "java/util/EmptyStackException.class" { reject("forbidden legacy stack API"); next; }
$0 == "java/util/StringTokenizer.class" { reject("forbidden legacy tokenizer API"); next; }
$0 ~ /^java\/util\/Collections\$(RandomAccess)?Synchronized/ { reject("forbidden synchronized collection wrapper"); next; }
$0 ~ /^java\/lang\/invoke\// { reject("forbidden method-handle and invokedynamic API"); next; }
$0 ~ /^java\/lang\/reflect\// { reject("forbidden reflection API"); next; }

$0 ~ /^sun\// {
  reject("unexpected sun internal class");
  next;
}

$0 ~ /^avata\// { next; }
$0 ~ /^java\/lang\// { next; }
$0 ~ /^java\/io\// { next; }
$0 ~ /^java\/util\// { next; }
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
