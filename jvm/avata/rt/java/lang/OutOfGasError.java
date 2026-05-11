/* TOS Network – TOS JVM contract runtime.
   Licensed under the Apache License, Version 2.0 (same as the Avata fork).

   OutOfGasError is thrown by the interpreter dispatch loop (interpret.cpp)
   when the per-transaction gas counter reaches zero.  It is always thrown
   deterministically: every validator that runs the same transaction with the
   same gas_limit will throw at the same bytecode offset.

   The gas counter is initialized by jvm/core/compute-phase.cpp from the
   gas_limit field of WorkchainComputeInput before contract execution begins.
   Gas costs per opcode are loaded from ConfigParam 85 by the JVM workchain
   adapter and installed into the interpreter's gas table before execution.

   It extends Error (not RuntimeException) so normal application-level
   Exception handlers do not catch it.  Validators treat an OutOfGasError as
   an abrupt termination: gas_used equals gas_limit, no state changes are
   committed. */
package java.lang;

public final class OutOfGasError extends Error {
  public OutOfGasError() {
    super("out of gas");
  }

  public OutOfGasError(String message) {
    super(message);
  }
}
