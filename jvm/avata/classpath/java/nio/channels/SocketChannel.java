/* Copyright (c) 2008-2015, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for this software.  See license.txt for
   details. */

package java.nio.channels;

import java.io.IOException;
import java.net.SocketException;
import java.net.SocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;

// -------------------------------------------------------------------------
// Consensus-safe SocketChannel — Avata/TOS blockchain JVM
// All operations are TRAPPED with a deterministic UnsupportedOperationException.
// -------------------------------------------------------------------------
public class SocketChannel extends SelectableChannel
  implements ReadableByteChannel, GatheringByteChannel
{
  public static final int InvalidSocket = -1;

  private static final String MSG =
      "networking not available in consensus";

  // -----------------------------------------------------------------------
  // open() — TRAPPED
  // -----------------------------------------------------------------------
  public static SocketChannel open() throws IOException {
    throw new UnsupportedOperationException(MSG);
  }

  public SelectableChannel configureBlocking(boolean v) throws IOException {
    throw new UnsupportedOperationException(MSG);
  }

  public boolean isBlocking() {
    return true;
  }

  public boolean isConnected() {
    return false;
  }

  public Socket socket() {
    throw new UnsupportedOperationException(MSG);
  }

  public boolean connect(SocketAddress address) throws IOException {
    throw new UnsupportedOperationException(MSG);
  }

  public boolean finishConnect() throws IOException {
    throw new UnsupportedOperationException(MSG);
  }

  @Override
  public void close() throws IOException {
    // no-op: nothing was opened
  }

  public int read(ByteBuffer b) throws IOException {
    throw new UnsupportedOperationException(MSG);
  }

  public int write(ByteBuffer b) throws IOException {
    throw new UnsupportedOperationException(MSG);
  }

  public long write(ByteBuffer[] srcs) throws IOException {
    if (srcs == null) {
      throw new NullPointerException();
    }
    throw new UnsupportedOperationException(MSG);
  }

  public long write(ByteBuffer[] srcs, int offset, int length)
    throws IOException
  {
    if (srcs == null) {
      throw new NullPointerException();
    }
    if (offset < 0 || length < 0 || offset > srcs.length - length) {
      throw new IndexOutOfBoundsException();
    }
    throw new UnsupportedOperationException(MSG);
  }

  // Package-private helpers used by SocketSelector — raise on any use.
  int socketFD() {
    throw new UnsupportedOperationException(MSG);
  }

  void closeSocket() {
    // no-op
  }

  void handleReadyOps(int ops) {
    // no-op
  }
}
