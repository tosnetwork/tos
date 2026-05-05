/* TOS Network – TOS JVM contract runtime.
   Licensed under the Apache License, Version 2.0 (same as the Avata fork).

   ClassFormatError is thrown when the JVM encounters a class file that is
   malformed or that fails the class-file format constraints defined by the
   Java Virtual Machine Specification.  In the TOS consensus profile it is
   also thrown when a class file targets a forbidden Java version (see
   UnsupportedClassVersionError). */
package java.lang;

public class ClassFormatError extends LinkageError {
  public ClassFormatError() {
    super();
  }

  public ClassFormatError(String message) {
    super(message);
  }
}
