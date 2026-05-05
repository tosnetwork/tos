/* Copyright (c) 2008-2016, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for this software.  See license.txt for
   details. */

package java.lang.invoke;

/**
 * SerializedLambda is NOT admitted in the Avata consensus profile.
 *
 * Lambda serialization depends on writeReplace/readResolve mechanics and the
 * $deserializeLambda$ protocol, which involves java.io.ObjectOutputStream /
 * ObjectInputStream.  Object serialization itself is outside the admitted
 * consensus profile, and the $deserializeLambda$ reflective callback would be
 * host-observing (it looks up methods on arbitrary classes).
 *
 * The class is present only to satisfy the JDK8u API surface expected by
 * javac-generated invokedynamic bootstrap metadata.  All public methods and
 * the constructor throw UnsupportedOperationException with a deterministic
 * message so that code attempting to use lambda serialization fails loudly
 * rather than silently diverging.
 *
 * JDK8u: java.lang.invoke.SerializedLambda
 */
public final class SerializedLambda implements java.io.Serializable {
  private static final long serialVersionUID = 8025925345765570181L;

  private static final String MSG =
    "SerializedLambda is not supported in the Avata consensus profile";

  /**
   * NOT ADMITTED — lambda serialization is outside the consensus profile.
   * @throws UnsupportedOperationException always
   */
  public SerializedLambda(Class<?> capturingClass,
                          String functionalInterfaceClass,
                          String functionalInterfaceMethodName,
                          String functionalInterfaceMethodSignature,
                          int implMethodKind,
                          String implClass,
                          String implMethodName,
                          String implMethodSignature,
                          String instantiatedMethodType,
                          Object[] capturedArgs) {
    throw new UnsupportedOperationException(MSG);
  }

  public Class<?> getCapturingClass() {
    throw new UnsupportedOperationException(MSG);
  }

  public String getFunctionalInterfaceClass() {
    throw new UnsupportedOperationException(MSG);
  }

  public String getFunctionalInterfaceMethodName() {
    throw new UnsupportedOperationException(MSG);
  }

  public String getFunctionalInterfaceMethodSignature() {
    throw new UnsupportedOperationException(MSG);
  }

  public String getImplClass() {
    throw new UnsupportedOperationException(MSG);
  }

  public String getImplMethodName() {
    throw new UnsupportedOperationException(MSG);
  }

  public String getImplMethodSignature() {
    throw new UnsupportedOperationException(MSG);
  }

  public int getImplMethodKind() {
    throw new UnsupportedOperationException(MSG);
  }

  public String getInstantiatedMethodType() {
    throw new UnsupportedOperationException(MSG);
  }

  public int getCapturedArgCount() {
    throw new UnsupportedOperationException(MSG);
  }

  public Object getCapturedArg(int i) {
    throw new UnsupportedOperationException(MSG);
  }

  @Override
  public String toString() {
    throw new UnsupportedOperationException(MSG);
  }
}
