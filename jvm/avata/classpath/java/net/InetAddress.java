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
// Consensus-safe InetAddress — Avata/TOS blockchain JVM
//
// DNS resolution is a non-deterministic host operation and is TRAPPED.
// The class shape is preserved for linkage.
// -------------------------------------------------------------------------
public class InetAddress {
  private static final String MSG =
      "networking not available in consensus";

  private final String name;
  private final int ip;

  // Private constructor — reachable only from within this file
  private InetAddress(String name, int ip) {
    this.name = name;
    this.ip   = ip;
  }

  public String getHostName() {
    return name;
  }

  public String getHostAddress() {
    int a = ip;
    return ((a >>> 24) & 0xFF) + "." +
           ((a >>> 16) & 0xFF) + "." +
           ((a >>>  8) & 0xFF) + "." +
           ( a         & 0xFF);
  }

  // -----------------------------------------------------------------------
  // DNS lookup — TRAPPED
  // -----------------------------------------------------------------------
  public static InetAddress getByName(String name) throws UnknownHostException {
    throw new UnsupportedOperationException(MSG);
  }

  public byte[] getAddress() {
    byte[] res = new byte[4];
    res[0] = (byte) ( ip >>> 24);
    res[1] = (byte) ((ip >>> 16) & 0xFF);
    res[2] = (byte) ((ip >>>  8) & 0xFF);
    res[3] = (byte) ((ip       ) & 0xFF);
    return res;
  }

  @Override
  public String toString() {
    return getHostAddress();
  }

  public int getRawAddress() {
    return ip;
  }

  public boolean equals(Object o) {
    return o instanceof InetAddress && ((InetAddress) o).ip == ip;
  }

  public int hashCode() {
    return ip;
  }
}
