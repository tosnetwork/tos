/* TOS Network – TOS JVM contract runtime.
   Licensed under the Apache License, Version 2.0 (same as the Avata fork).

   ContractViolationError is thrown whenever a smart contract attempts an
   operation that is forbidden in the deterministic TOS execution profile.
   Examples: wall-clock time access, file/network I/O, thread creation,
   native library loading, and reflection outside the admitted surface.

   It extends Error (not RuntimeException) so that contract code cannot
   silently catch it and continue.  Validators must treat an unhandled
   ContractViolationError the same as any other abrupt contract termination:
   gas is consumed, no state changes are committed. */
package java.lang;

public final class ContractViolationError extends Error {
  public ContractViolationError() {
    super();
  }

  public ContractViolationError(String message) {
    super(message);
  }
}
