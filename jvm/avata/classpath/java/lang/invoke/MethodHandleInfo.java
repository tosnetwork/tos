/* Copyright (c) 2008-2016, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for this software.  See license.txt for
   details. */

package java.lang.invoke;

/**
 * Minimal MethodHandleInfo stub for the Avata consensus profile.
 * This interface exists only to satisfy the JDK8u API surface for
 * Lookup.revealDirect(), which itself throws UnsupportedOperationException.
 * No implementation is required or admitted.
 *
 * JDK8u: java.lang.invoke.MethodHandleInfo
 */
public interface MethodHandleInfo {
  // Reference kind constants from JDK8u
  int REF_getField         = 1;
  int REF_getStatic        = 2;
  int REF_putField         = 3;
  int REF_putStatic        = 4;
  int REF_invokeVirtual    = 5;
  int REF_invokeStatic     = 6;
  int REF_invokeSpecial    = 7;
  int REF_newInvokeSpecial = 8;
  int REF_invokeInterface  = 9;

  // All methods below are not admitted — no implementation is provided.
  // The only path to obtain a MethodHandleInfo is Lookup.revealDirect(),
  // which itself throws UnsupportedOperationException.

  int getReferenceKind();
  Class<?> getDeclaringClass();
  String getName();
  MethodType getMethodType();

  default <T extends java.lang.reflect.Member> T reflectAs(Class<T> expected,
                                                            MethodHandles.Lookup lookup) {
    throw new UnsupportedOperationException(
      "MethodHandleInfo is not supported in the Avata consensus profile");
  }
}
