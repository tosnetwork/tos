/* Copyright (c) 2026, TOS Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for details. */

package java.internal;

public final class Memory {
  private Memory() { }

  public static native long used();

  public static native long remaining();

  public static native long limit();
}
