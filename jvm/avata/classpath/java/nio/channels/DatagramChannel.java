/* Copyright (c) 2008-2015, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for this software.  See license.txt for
   details. */

package java.nio.channels;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.net.SocketAddress;
import java.net.ProtocolFamily;
import java.net.DatagramSocket;

// -------------------------------------------------------------------------
// Consensus-safe DatagramChannel — Avata/TOS blockchain JVM
// All operations are TRAPPED.
// -------------------------------------------------------------------------
public class DatagramChannel extends SelectableChannel
  implements ReadableByteChannel, WritableByteChannel
{
  public static final int InvalidSocket = -1;

  private static final String MSG =
      "networking not available in consensus";

  public SelectableChannel configureBlocking(boolean v) throws IOException {
    throw new UnsupportedOperationException(MSG);
  }

  int socketFD() {
    throw new UnsupportedOperationException(MSG);
  }

  void handleReadyOps(int ops) {
    // no-op
  }

  public static DatagramChannel open(ProtocolFamily family)
    throws IOException
  {
    throw new UnsupportedOperationException(MSG);
  }

  public static DatagramChannel open()
    throws IOException
  {
    throw new UnsupportedOperationException(MSG);
  }

  public DatagramSocket socket() {
    throw new UnsupportedOperationException(MSG);
  }

  public DatagramChannel bind(SocketAddress address) throws IOException {
    throw new UnsupportedOperationException(MSG);
  }

  public DatagramChannel connect(SocketAddress address) throws IOException {
    throw new UnsupportedOperationException(MSG);
  }

  public int write(ByteBuffer b) throws IOException {
    throw new UnsupportedOperationException(MSG);
  }

  public int read(ByteBuffer b) throws IOException {
    throw new UnsupportedOperationException(MSG);
  }

  public SocketAddress receive(ByteBuffer b) throws IOException {
    throw new UnsupportedOperationException(MSG);
  }

  public int send(ByteBuffer b, SocketAddress address) throws IOException {
    throw new UnsupportedOperationException(MSG);
  }

  public boolean isConnected() {
    return false;
  }

  public DatagramChannel disconnect() throws IOException {
    throw new UnsupportedOperationException(MSG);
  }

  public void close() throws IOException {
    // no-op
  }
}
