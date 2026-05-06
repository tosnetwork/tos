# proguard include file (http://proguard.sourceforge.net)

# Enums have methods and members that are called reflectively in both Avata and OpenJDK.
-keepclassmembers enum * {
    **[] $VALUES;
    public *;
    public static **[] values();
}

# the VM depends on the fixed layout of the following classes:

-keepclassmembers class java.lang.Class { !static <fields>; }
-keepclassmembers class avata.ClassSpace { !static <fields>; }
-keepclassmembers class java.lang.String { !static <fields>; }
-keepclassmembers class avata.ExecutionContext { !static <fields>; }
-keepclassmembers class avata.ExecutionGroup { !static <fields>; }
-keepclassmembers class java.lang.StackTraceElement { !static <fields>; }
-keepclassmembers class java.lang.Throwable { !static <fields>; }
-keepclassmembers class java.lang.Byte { !static <fields>; }
-keepclassmembers class java.lang.Boolean { !static <fields>; }
-keepclassmembers class java.lang.Short { !static <fields>; }
-keepclassmembers class java.lang.Character { !static <fields>; }
-keepclassmembers class java.lang.Integer { !static <fields>; }
-keepclassmembers class java.lang.Long { !static <fields>; }
-keepclassmembers class java.lang.Float { !static <fields>; }
-keepclassmembers class java.lang.Double { !static <fields>; }
-keepclassmembers class avata.VMClass { !static <fields>; }
-keepclassmembers class avata.VMMethod { !static <fields>; }
-keepclassmembers class avata.VMField { !static <fields>; }
-keepclassmembers class avata.ClassAddendum { !static <fields>; }
-keepclassmembers class avata.MethodAddendum { !static <fields>; }
-keepclassmembers class avata.FieldAddendum { !static <fields>; }
# the VM may throw instances of the following:

-keep public class java.lang.Exception
-keep public class java.lang.RuntimeException
-keep public class java.lang.IllegalStateException
-keep public class java.lang.IllegalArgumentException
-keep public class java.lang.IllegalMonitorStateException
-keep public class java.lang.IndexOutOfBoundsException
-keep public class java.lang.ArrayIndexOutOfBoundsException
-keep public class java.lang.ArrayStoreException
-keep public class java.lang.NegativeArraySizeException
-keep public class java.lang.CloneNotSupportedException
-keep public class java.lang.ClassCastException
-keep public class java.lang.ClassNotFoundException
-keep public class java.lang.NullPointerException
-keep public class java.lang.ArithmeticException
-keep public class java.lang.InterruptedException
-keep public class java.lang.StackOverflowError
-keep public class java.lang.NoSuchFieldError
-keep public class java.lang.NoSuchMethodError
-keep public class java.lang.AbstractMethodError
-keep public class java.lang.UnsatisfiedLinkError
-keep public class java.lang.ExceptionInInitializerError
-keep public class java.lang.OutOfMemoryError
-keep public class java.lang.IncompatibleClassChangeError
-keep public class java.io.IOException

# The VM-internal fixed classpath loader depends on the existence of this class:

-keep             class avata.SystemClassSpace

# the VM references these classes by name, so protect them from obfuscation:

-keepnames public class java.lang.**
-keepnames public class avata.**

# Don't optimize calls to ResourceBundle
-keep,allowshrinking,allowobfuscation public class java.util.ResourceBundle {
  public static java.util.ResourceBundle getBundle(...);
}

# musn't obfuscate native method names:

-keepclasseswithmembernames class * {
   native <methods>;
 }

# ExecutionContext.run is called by name in the VM

-keepclassmembers class avata.ExecutionContext {
   private static void run(avata.ExecutionContext);
   public void run();
}

# Proguard gets confused about clone() and array classes (http://sourceforge.net/tracker/index.php?func=detail&aid=2851344&group_id=54750&atid=474704):

-keepclassmembers class java.lang.Object {
   protected java.lang.Object clone();
 }

# called by name in the VM:

-keepclassmembers class avata.ClassSpace {
   public java.lang.Class loadClass(java.lang.String);
 }

 -keepclassmembers class avata.Classes {
   public java.security.ProtectionDomain getProtectionDomain(avata.VMClass);
 }
