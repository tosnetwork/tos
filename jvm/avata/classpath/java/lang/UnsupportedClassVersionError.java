/* TOS Network – TOS JVM contract runtime.
   Licensed under the Apache License, Version 2.0 (same as the Avata fork).

   UnsupportedClassVersionError is thrown by the class reader in machine.cpp
   when a class file targets a Java version outside the admitted TOS consensus
   profile (Java 8, major version 52).  Class files compiled for Java 9 or
   later (major version >= 53) use module-system constructs and invokedynamic
   patterns that are outside the deterministic execution profile. */
package java.lang;

public class UnsupportedClassVersionError extends ClassFormatError {
  public UnsupportedClassVersionError() {
    super();
  }

  public UnsupportedClassVersionError(String message) {
    super(message);
  }
}
