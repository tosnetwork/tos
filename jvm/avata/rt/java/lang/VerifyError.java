/* TOS Network - TOS JVM contract runtime.
   Licensed under the Apache License, Version 2.0 (same as the Avata fork). */

package java.lang;

public class VerifyError extends LinkageError {
  public VerifyError() {
    super();
  }

  public VerifyError(String message) {
    super(message);
  }
}
