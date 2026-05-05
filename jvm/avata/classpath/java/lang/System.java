/* Copyright (c) 2008-2015, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for this software.  See license.txt for
   details. */

package java.lang;

import java.io.PrintStream;
import java.io.InputStream;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileDescriptor;
import java.util.Map;
import java.util.Properties;

// -------------------------------------------------------------------------
// Consensus-safe System — Avata/TOS blockchain JVM
//
// Non-deterministic host paths are trapped with UnsupportedOperationException
// carrying a fixed constant message so every node raises the same exception.
// -------------------------------------------------------------------------
public abstract class System {

  // Trap messages — kept as compile-time constants so they are deterministic.
  private static final String MSG_TIME =
      "wall-clock time not available in consensus";
  private static final String MSG_ENV =
      "environment variables not available in consensus";
  private static final String MSG_NATIVE =
      "native library loading not available in consensus";
  private static final String MSG_EXIT =
      "System.exit not available in consensus";
  private static final String MSG_NET =
      "networking not available in consensus";

  // Deterministic property set — only keys whose values are
  // platform-independent and byte-identical across all nodes.
  private static final Properties PROPERTIES = makeProperties();

  private static Properties makeProperties() {
    Properties p = new Properties();
    p.put("java.version",       "1.8.0");
    p.put("java.class.version", "52.0");
    p.put("file.separator",     "/");
    p.put("path.separator",     ":");
    p.put("line.separator",     "\n");
    p.put("file.encoding",      "UTF-8");
    // Deterministic locale — fixed to English/US so Locale.DEFAULT is stable
    // across all nodes.  user.language and user.region must not be host-derived.
    p.put("user.language",      "en");
    p.put("user.region",        "US");
    // os.name is needed by java/io/File to detect the path separator.
    // Fixed to "Linux" (POSIX paths) for all consensus nodes.
    p.put("os.name",            "Linux");
    // java.io.tmpdir is needed by libraries that create temp files.
    // Paths are in-memory only; host filesystem access is not available.
    p.put("java.io.tmpdir",     "/tmp");
    // user.dir is the working directory — fixed to "/" in the consensus VM.
    p.put("user.dir",           "/");
    return p;
  }

  // Standard streams — kept as host stdio stubs so System.out.println works
  // inside consensus code (outputs go to the node log, not the ledger state).
  public static final PrintStream out = new PrintStream
    (new BufferedOutputStream(new FileOutputStream(FileDescriptor.out)), true);

  public static final PrintStream err = new PrintStream
    (new BufferedOutputStream(new FileOutputStream(FileDescriptor.err)), true);

  public static final InputStream in
    = new BufferedInputStream(new FileInputStream(FileDescriptor.in));

  // -----------------------------------------------------------------------
  // arraycopy — admitted; delegates to native implementation
  // -----------------------------------------------------------------------
  public static native void arraycopy(Object src, int srcOffset, Object dst,
                                      int dstOffset, int length);

  // -----------------------------------------------------------------------
  // identityHashCode — MUST NOT leak object address.
  // The native objectHash() in classpath-avata.cpp already uses a
  // deterministic hash (not the raw pointer), so we keep it.
  // -----------------------------------------------------------------------
  public static native int identityHashCode(Object o);

  // -----------------------------------------------------------------------
  // Wall-clock time — TRAPPED
  // -----------------------------------------------------------------------
  public static long currentTimeMillis() {
    throw new UnsupportedOperationException(MSG_TIME);
  }

  public static long nanoTime() {
    throw new UnsupportedOperationException(MSG_TIME);
  }

  // -----------------------------------------------------------------------
  // Environment variables — TRAPPED
  // -----------------------------------------------------------------------
  public static String getenv(String name) {
    throw new UnsupportedOperationException(MSG_ENV);
  }

  public static Map<String, String> getenv() {
    throw new UnsupportedOperationException(MSG_ENV);
  }

  // -----------------------------------------------------------------------
  // System properties — only deterministic keys are exposed
  // -----------------------------------------------------------------------
  public static String getProperty(String name) {
    return (String) PROPERTIES.get(name);
  }

  public static String getProperty(String name, String defaultValue) {
    String result = getProperty(name);
    return (result != null) ? result : defaultValue;
  }

  /**
   * setProperty is permitted within a single execution context (smart
   * contract may configure its own properties) but host-derived keys
   * must not be re-injected.  We accept the call and update the local
   * in-execution map.
   */
  public static String setProperty(String name, String value) {
    return (String) PROPERTIES.put(name, value);
  }

  public static String clearProperty(String name) {
    return (String) PROPERTIES.remove(name);
  }

  public static Properties getProperties() {
    // Return the deterministic set; callers may read but not modify host info.
    return PROPERTIES;
  }

  // -----------------------------------------------------------------------
  // Library loading — TRAPPED
  // -----------------------------------------------------------------------
  public static String mapLibraryName(String name) {
    throw new UnsupportedOperationException(MSG_NATIVE);
  }

  public static void load(String path) {
    throw new UnsupportedOperationException(MSG_NATIVE);
  }

  public static void loadLibrary(String name) {
    throw new UnsupportedOperationException(MSG_NATIVE);
  }

  // -----------------------------------------------------------------------
  // GC / finalization — made no-ops; running GC is deterministic in Avata
  // (the heap is heap-isolated per execution) so we delegate to the VM.
  // -----------------------------------------------------------------------
  public static void gc() {
    Runtime.getRuntime().gc();
  }

  public static void runFinalization() {
    // no-op: finalizers are non-deterministic; suppress silently
  }

  // -----------------------------------------------------------------------
  // Process exit — TRAPPED
  // -----------------------------------------------------------------------
  public static void exit(int code) {
    throw new UnsupportedOperationException(MSG_EXIT);
  }

  // -----------------------------------------------------------------------
  // SecurityManager stubs — no-op in the consensus VM
  // -----------------------------------------------------------------------
  public static SecurityManager getSecurityManager() {
    return null;
  }

  public static void setSecurityManager(SecurityManager sm) {
    // ignored in the consensus VM
  }
}
