/* Copyright (c) 2008-2016, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for this software.  See license.txt for
   details. */

package java.lang.invoke;

/**
 * MutableCallSite is NOT admitted in the Avata consensus profile.
 * It allows runtime target mutation which breaks determinism across nodes.
 * All public constructors and the syncAll static method throw
 * UnsupportedOperationException with a deterministic message.
 *
 * JDK8u: java.lang.invoke.MutableCallSite
 */
public class MutableCallSite extends CallSite {

  private static final String MSG =
    "MutableCallSite is not supported in the Avata consensus profile";

  public MutableCallSite(MethodType type) {
    super(null);
    throw new UnsupportedOperationException(MSG);
  }

  public MutableCallSite(MethodHandle target) {
    super(null);
    throw new UnsupportedOperationException(MSG);
  }

  @Override
  public MethodHandle getTarget() {
    throw new UnsupportedOperationException(MSG);
  }

  @Override
  public void setTarget(MethodHandle newTarget) {
    throw new UnsupportedOperationException(MSG);
  }

  @Override
  public MethodHandle dynamicInvoker() {
    throw new UnsupportedOperationException(MSG);
  }

  public static void syncAll(MutableCallSite[] sites) {
    throw new UnsupportedOperationException(MSG);
  }
}
