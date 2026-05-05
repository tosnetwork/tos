/* Copyright (c) 2008-2016, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for this software.  See license.txt for
   details. */

package java.lang.invoke;

/**
 * A ConstantCallSite is a CallSite whose target is permanent and can never be
 * changed.  This is the only CallSite subclass admitted in the Avata consensus
 * profile (it is what LambdaMetafactory produces for invokedynamic bootstrap).
 *
 * JDK8u: java.lang.invoke.ConstantCallSite
 */
public final class ConstantCallSite extends CallSite {

  /**
   * Creates a call site with a permanent target.
   *
   * @param target the target to be permanently associated with this call site
   * @throws NullPointerException if target is null
   */
  public ConstantCallSite(MethodHandle target) {
    super(target);
  }

  /**
   * Returns the permanent target of this call site.
   *
   * @return the immutable target method handle
   */
  @Override
  public MethodHandle getTarget() {
    return target;
  }

  /**
   * Always throws UnsupportedOperationException — a ConstantCallSite cannot
   * change its target.
   *
   * @throws UnsupportedOperationException always
   */
  @Override
  public void setTarget(MethodHandle ignore) {
    throw new UnsupportedOperationException();
  }

  /**
   * Returns this call site's permanent target, which is its own dynamic
   * invoker since it never changes.
   *
   * @return the permanent target method handle
   */
  @Override
  public MethodHandle dynamicInvoker() {
    return target;
  }
}
