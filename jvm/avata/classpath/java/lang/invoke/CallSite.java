/* Copyright (c) 2008-2016, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for this software.  See license.txt for
   details. */

package java.lang.invoke;

/**
 * Avata consensus profile: CallSite is abstract per JDK8u.
 * Only ConstantCallSite is admitted (bootstrap-method path).
 * MutableCallSite and VolatileCallSite allow runtime target mutation
 * and are NOT admitted — their constructors throw UnsupportedOperationException.
 */
public abstract class CallSite {
  MethodHandle target;

  CallSite(MethodHandle target) {
    this.target = target;
  }

  /** Returns the type of this call site's target. */
  public MethodType type() {
    return target.type();
  }

  /** Returns the current target method handle according to subclass semantics. */
  public abstract MethodHandle getTarget();

  /** Sets the target (always throws for ConstantCallSite; admitted only there). */
  public abstract void setTarget(MethodHandle newTarget);

  /** Returns a method handle that delegates calls to this call site's current target. */
  public abstract MethodHandle dynamicInvoker();
}
