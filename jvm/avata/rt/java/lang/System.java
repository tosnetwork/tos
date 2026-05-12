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
import java.io.OutputStream;
import java.io.IOException;
import java.util.Map;
import java.util.TreeMap;

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
  // Deterministic property set — only fixed keys whose values are
  // platform-independent and byte-identical across all nodes.
  private static final Map<String, String> PROPERTIES = makeProperties();

  private static Map<String, String> makeProperties() {
    Map<String, String> p = new TreeMap<String, String>();
    p.put("java.version",       "1.8.0");
    p.put("java.class.version", "52.0");
    p.put("file.separator",     "/");
    p.put("path.separator",     ":");
    p.put("line.separator",     "\n");
    p.put("file.encoding",      "UTF-8");
    // Deterministic language metadata. The v1 profile does not ship Locale,
    // but these keys must still not be host-derived.
    p.put("user.language",      "en");
    p.put("user.region",        "US");
    // Compatibility-only values. Path-based File APIs are not shipped in the
    // v1 profile, but a few libraries read these properties defensively.
    p.put("os.name",            "Linux");
    p.put("java.io.tmpdir",     "/tmp");
    p.put("user.dir", ".");
    return p;
  }

  // Standard streams — kept as host stdio stubs so System.out.println works
  // inside consensus code (outputs go to the node log, not the ledger state).
  public static final PrintStream out = new PrintStream
    (new BufferedOutputStream(new StandardOutputStream(false)), true);

  public static final PrintStream err = new PrintStream
    (new BufferedOutputStream(new StandardOutputStream(true)), true);

  public static final InputStream in
    = new BufferedInputStream(new StandardInputStream());

  private static final class StandardInputStream extends InputStream {
    public int read() throws IOException {
      return -1;
    }

    public int read(byte[] b, int offset, int length) throws IOException {
      if (b == null) {
        throw new NullPointerException();
      }

      if (offset < 0 || length < 0 || offset > b.length - length) {
        throw new ArrayIndexOutOfBoundsException();
      }

      if (length == 0) {
        return 0;
      }

      return -1;
    }
  }

  private static final class StandardOutputStream extends OutputStream {
    private final boolean error;

    StandardOutputStream(boolean error) {
      this.error = error;
    }

    public void write(int c) throws IOException {
      if (error) {
        writeStderrByte(c);
      } else {
        writeStdoutByte(c);
      }
    }

    public void write(byte[] b, int offset, int length) throws IOException {
      if (b == null) {
        throw new NullPointerException();
      }

      if (offset < 0 || length < 0 || offset > b.length - length) {
        throw new ArrayIndexOutOfBoundsException();
      }

      if (length == 0) {
        return;
      }

      if (error) {
        writeStderr(b, offset, length);
      } else {
        writeStdout(b, offset, length);
      }
    }
  }

  private static native void writeStdoutByte(int c);

  private static native void writeStdout(byte[] b, int offset, int length);

  private static native void writeStderrByte(int c);

  private static native void writeStderr(byte[] b, int offset, int length);

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
    return PROPERTIES.get(name);
  }

  public static String getProperty(String name, String defaultValue) {
    String result = getProperty(name);
    return (result != null) ? result : defaultValue;
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
  // Process exit — TRAPPED
  // -----------------------------------------------------------------------
  public static void exit(int code) {
    throw new UnsupportedOperationException(MSG_EXIT);
  }

  // -----------------------------------------------------------------------
  // Outbound internal message — admitted.
  //
  // Stages an action_send_msg cell that the host appends to the
  // transaction's action_list on commit.  Failed calls (revert /
  // OutOfGas / OutOfMemory) discard pending messages alongside storage
  // writes and events, so a contract that emits N messages and then
  // reverts emits zero.
  //
  // Cross-contract invocation is asynchronous: the receiving contract
  // executes in a later transaction within the same block, not inline.
  // Use this primitive for transfers and for one-shot calls into other
  // contracts; the call response (if any) lands as a separate inbound
  // message back to the sender.
  // -----------------------------------------------------------------------
  public static void sendMessage(Address dest, Uint256 value, byte[] body) {
    if (dest == null) {
      throw new NullPointerException("System.sendMessage dest cannot be null");
    }
    if (value == null) {
      throw new NullPointerException("System.sendMessage value cannot be null");
    }
    if (body == null) {
      throw new NullPointerException("System.sendMessage body cannot be null");
    }
    nativeSendMessage(dest.workchain(),
                      dest.accountIdBytes(),
                      value.toByteArray(),
                      body);
  }

  /** Convenience overload — passes the empty body. */
  public static void sendMessage(Address dest, Uint256 value) {
    sendMessage(dest, value, new byte[0]);
  }

  private static native void nativeSendMessage(int destWorkchain,
                                               byte[] destAddr,
                                               byte[] value,
                                               byte[] body);

  // -----------------------------------------------------------------------
  // Outbound action_create_account — admitted.
  //
  // Stages an action_create_account#4a435241 cell that the host appends
  // to the transaction's action_list on commit.  Destination workchain
  // is implicitly the emitter's own (wc=3 for any caller running under
  // JvmNativeEngine; the host action phase enforces
  // `dest.workchain = account.workchain`).
  //
  // `stateInit` is the raw BOC of a `StateInit` cell that the host
  // will install on the new account when the activating internal
  // message arrives.  For a wc=3 JVM contract the canonical shape is
  // `StateInit { code = ^marker(0x4a), data = ^JvmContractAccountState }`
  // — see `encode_jvm_state_init_cell` in jvm/core/cell-codec.cpp.
  //
  // The caller is responsible for producing a consensus-valid BOC; the
  // host parses it before staging and rejects malformed input.
  //
  // Cross-contract account materialization is asynchronous in the same
  // sense as sendMessage: the new account becomes live in the next
  // transaction within the same block.  Failed calls (revert /
  // OutOfGas / OutOfMemory) discard pending createAccount actions
  // alongside storage writes, events, and outbound messages.
  // -----------------------------------------------------------------------
  public static void createAccount(Address dest, byte[] stateInit,
                                   Uint256 value, byte[] body) {
    if (dest == null) {
      throw new NullPointerException(
          "System.createAccount dest cannot be null");
    }
    if (stateInit == null) {
      throw new NullPointerException(
          "System.createAccount stateInit cannot be null");
    }
    if (stateInit.length == 0) {
      throw new IllegalArgumentException(
          "System.createAccount stateInit must not be empty");
    }
    if (value == null) {
      throw new NullPointerException(
          "System.createAccount value cannot be null");
    }
    if (body == null) {
      throw new NullPointerException(
          "System.createAccount body cannot be null");
    }
    nativeCreateAccount(dest.accountIdBytes(),
                        stateInit,
                        value.toByteArray(),
                        body);
  }

  /** Convenience overload — passes the empty body. */
  public static void createAccount(Address dest, byte[] stateInit,
                                   Uint256 value) {
    createAccount(dest, stateInit, value, new byte[0]);
  }

  private static native void nativeCreateAccount(byte[] destAddr,
                                                 byte[] stateInit,
                                                 byte[] value,
                                                 byte[] body);
}
