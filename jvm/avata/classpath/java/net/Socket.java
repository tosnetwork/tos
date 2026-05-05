/* Copyright (c) 2008-2015, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for this software.  See license.txt for
   details. */

package java.net;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

// -------------------------------------------------------------------------
// Consensus-safe Socket — Avata/TOS blockchain JVM
//
// All networking operations are TRAPPED with a deterministic
// UnsupportedOperationException.  The class shape (fields / inner classes)
// is preserved for class-file linking compatibility.
// -------------------------------------------------------------------------
public class Socket implements Closeable, AutoCloseable {

  private static final String MSG =
      "networking not available in consensus";

  // -----------------------------------------------------------------------
  // Winsock bootstrap — kept as no-op so SocketChannel.open() linkage
  // survives; actual networking is trapped before any native call.
  // -----------------------------------------------------------------------
  public static void init() throws IOException {
    // no-op in consensus mode — native init is never reached
  }

  // -----------------------------------------------------------------------
  // Constructors — ALL TRAPPED
  // -----------------------------------------------------------------------
  public Socket() throws IOException {
    throw new UnsupportedOperationException(MSG);
  }

  protected Socket(boolean create) throws IOException {
    throw new UnsupportedOperationException(MSG);
  }

  public Socket(InetAddress address, int port) throws IOException {
    throw new UnsupportedOperationException(MSG);
  }

  public Socket(String host, int port) throws UnknownHostException, IOException {
    throw new UnsupportedOperationException(MSG);
  }

  // -----------------------------------------------------------------------
  // Instance operations — ALL TRAPPED (should never be reached given
  // that constructors trap, but guard them anyway for safety)
  // -----------------------------------------------------------------------
  public InputStream getInputStream() throws IOException {
    throw new UnsupportedOperationException(MSG);
  }

  public OutputStream getOutputStream() throws IOException {
    throw new UnsupportedOperationException(MSG);
  }

  public void bind(SocketAddress bindpoint) throws IOException {
    throw new UnsupportedOperationException(MSG);
  }

  public void connect(SocketAddress endpoint) throws IOException {
    throw new UnsupportedOperationException(MSG);
  }

  public void connect(SocketAddress endpoint, int timeout) throws IOException {
    throw new UnsupportedOperationException(MSG);
  }

  public void setTcpNoDelay(boolean on) throws SocketException {
    throw new UnsupportedOperationException(MSG);
  }

  public void shutdownInput() throws IOException {
    throw new UnsupportedOperationException(MSG);
  }

  public void shutdownOutput() throws IOException {
    throw new UnsupportedOperationException(MSG);
  }

  public SocketAddress getRemoteSocketAddress() {
    throw new UnsupportedOperationException(MSG);
  }

  public SocketAddress getLocalSocketAddress() {
    throw new UnsupportedOperationException(MSG);
  }

  @Override
  public void close() throws IOException {
    // close on a never-opened socket is a no-op (defensive)
  }
}
