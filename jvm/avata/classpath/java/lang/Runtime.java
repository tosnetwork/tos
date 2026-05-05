/* Copyright (c) 2008-2015, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for this software.  See license.txt for
   details. */

package java.lang;

import java.io.IOException;

// -------------------------------------------------------------------------
// Consensus-safe Runtime — Avata/TOS blockchain JVM
//
// Every host-observing method is replaced with a deterministic trap.
// -------------------------------------------------------------------------
public class Runtime {
  private static final Runtime instance = new Runtime();

  private static final String MSG_EXEC =
      "process execution not available in consensus";
  private static final String MSG_NATIVE =
      "native library loading not available in consensus";
  private static final String MSG_HALT =
      "Runtime.halt not available in consensus";
  private static final String MSG_HOOK =
      "shutdown hooks not available in consensus";

  // Fixed, deterministic "available processors" for consensus execution.
  // Smart contracts must not branch on actual hardware concurrency.
  private static final int CONSENSUS_PROCESSORS = 1;

  private Runtime() { }

  public static Runtime getRuntime() {
    return instance;
  }

  // -----------------------------------------------------------------------
  // Process execution — TRAPPED
  // -----------------------------------------------------------------------
  public Process exec(String command) throws IOException {
    throw new UnsupportedOperationException(MSG_EXEC);
  }

  public Process exec(String[] command) throws IOException {
    throw new UnsupportedOperationException(MSG_EXEC);
  }

  public Process exec(String command, String[] envp) throws IOException {
    throw new UnsupportedOperationException(MSG_EXEC);
  }

  public Process exec(String[] command, String[] envp) throws IOException {
    throw new UnsupportedOperationException(MSG_EXEC);
  }

  // -----------------------------------------------------------------------
  // Native library loading — TRAPPED
  // -----------------------------------------------------------------------
  public void load(String path) {
    throw new UnsupportedOperationException(MSG_NATIVE);
  }

  public void loadLibrary(String name) {
    throw new UnsupportedOperationException(MSG_NATIVE);
  }

  // -----------------------------------------------------------------------
  // Process termination — TRAPPED
  // -----------------------------------------------------------------------
  public void halt(int status) {
    throw new UnsupportedOperationException(MSG_HALT);
  }

  public void exit(int code) {
    throw new UnsupportedOperationException(
        "System.exit not available in consensus");
  }

  // -----------------------------------------------------------------------
  // Shutdown hooks — TRAPPED (non-deterministic execution ordering)
  // -----------------------------------------------------------------------
  public void addShutdownHook(Thread t) {
    throw new UnsupportedOperationException(MSG_HOOK);
  }

  public boolean removeShutdownHook(Thread t) {
    throw new UnsupportedOperationException(MSG_HOOK);
  }

  // -----------------------------------------------------------------------
  // Hardware / memory queries — return fixed deterministic values
  // -----------------------------------------------------------------------
  public int availableProcessors() {
    return CONSENSUS_PROCESSORS;
  }

  /** Returns the VM heap remaining — deterministic within one execution. */
  public native long freeMemory();

  /** Returns the VM heap limit — deterministic within one execution. */
  public native long totalMemory();

  /** Returns the VM heap limit — deterministic within one execution. */
  public native long maxMemory();

  // -----------------------------------------------------------------------
  // GC / finalization
  //
  // gc() is delegated to the VM collector which is deterministic (same
  // object graph, same collection result).  runFinalization() is a no-op
  // because finalizer ordering is non-deterministic.
  // -----------------------------------------------------------------------
  public native void gc();

  public void runFinalization() {
    // no-op: finalizer execution order is non-deterministic
  }
}
