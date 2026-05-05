/* Copyright (c) 2008-2015, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for this software.  See license.txt for
   details. */

package java.util;

public final class UUID implements java.io.Serializable, Comparable<UUID> {
  private static final long serialVersionUID = -4856846361193249489L;

  private final long mostSigBits;
  private final long leastSigBits;

  public UUID(long mostSigBits, long leastSigBits) {
    this.mostSigBits = mostSigBits;
    this.leastSigBits = leastSigBits;
  }

  /**
   * Traps randomUUID() — non-deterministic; not admitted in the consensus profile.
   */
  public static UUID randomUUID() {
    throw new UnsupportedOperationException(
      "UUID.randomUUID() is non-deterministic and not admitted in the consensus profile");
  }

  public static UUID fromString(String name) {
    if (name == null) throw new NullPointerException();
    String[] parts = name.split("-");
    if (parts.length != 5) {
      throw new IllegalArgumentException("Invalid UUID string: " + name);
    }
    try {
      long msb = (Long.parseLong(parts[0], 16) << 32)
               | (Long.parseLong(parts[1], 16) << 16)
               |  Long.parseLong(parts[2], 16);
      long lsb = (Long.parseLong(parts[3], 16) << 48)
               |  Long.parseLong(parts[4], 16);
      return new UUID(msb, lsb);
    } catch (NumberFormatException e) {
      throw new IllegalArgumentException("Invalid UUID string: " + name, e);
    }
  }

  public long getMostSignificantBits() {
    return mostSigBits;
  }

  public long getLeastSignificantBits() {
    return leastSigBits;
  }

  public int version() {
    return (int) ((mostSigBits >> 12) & 0xf);
  }

  public int variant() {
    long lsb = leastSigBits;
    if ((lsb >>> 63) == 0) return 0;
    if ((lsb >>> 62) == 2L) return 2;
    return (int) (lsb >>> 61);
  }

  public String toString() {
    return (digits(mostSigBits >> 32, 8) + "-" +
            digits(mostSigBits >> 16, 4) + "-" +
            digits(mostSigBits,       4) + "-" +
            digits(leastSigBits >> 48, 4) + "-" +
            digits(leastSigBits,       12));
  }

  private static String digits(long val, int digits) {
    long hi = 1L << (digits * 4);
    return Long.toHexString(hi | (val & (hi - 1))).substring(1);
  }

  public int hashCode() {
    long hilo = mostSigBits ^ leastSigBits;
    return ((int)(hilo >> 32)) ^ (int) hilo;
  }

  public boolean equals(Object obj) {
    if (!(obj instanceof UUID)) return false;
    UUID other = (UUID) obj;
    return mostSigBits == other.mostSigBits && leastSigBits == other.leastSigBits;
  }

  public int compareTo(UUID other) {
    int cmp = Long.compare(mostSigBits, other.mostSigBits);
    if (cmp != 0) return cmp;
    return Long.compare(leastSigBits, other.leastSigBits);
  }
}
