/* Copyright (c) 2008-2015, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for this software.  See license.txt for
   details. */

package java.nio.channels;

import java.io.IOException;

import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.ServerSocket;
import java.net.Socket;

// -------------------------------------------------------------------------
// Consensus-safe ServerSocketChannel — Avata/TOS blockchain JVM
// All operations are TRAPPED.
// -------------------------------------------------------------------------
public class ServerSocketChannel extends SelectableChannel {

  private static final String MSG =
      "networking not available in consensus";

  private ServerSocketChannel() { }

  public static ServerSocketChannel open() throws IOException {
    throw new UnsupportedOperationException(MSG);
  }

  public int socketFD() {
    throw new UnsupportedOperationException(MSG);
  }

  public void handleReadyOps(int ops) {
    // no-op
  }

  public SelectableChannel configureBlocking(boolean v) throws IOException {
    throw new UnsupportedOperationException(MSG);
  }

  public void close() throws IOException {
    // no-op
  }

  public SocketChannel accept() throws IOException {
    throw new UnsupportedOperationException(MSG);
  }

  public ServerSocket socket() {
    throw new UnsupportedOperationException(MSG);
  }
}
