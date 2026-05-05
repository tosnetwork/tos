/* Copyright (c) 2008-2015, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for this software.  See license.txt for
   details. */

package java.net;

import java.io.IOException;

// -------------------------------------------------------------------------
// Consensus-safe ServerSocket — Avata/TOS blockchain JVM
// All operations are TRAPPED.
// -------------------------------------------------------------------------
public abstract class ServerSocket {
  private static final String MSG =
      "networking not available in consensus";

  public abstract void bind(SocketAddress address) throws IOException;

  public void close() throws IOException {
    // no-op
  }
}
