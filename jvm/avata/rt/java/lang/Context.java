package java.lang;

// Per-call chain context for Avata/TOS JVM contracts (wc=3).
//
// All values are pinned for the duration of a single contract invocation by
// the workchain runtime (see jvm/core/avata-runtime.cpp). Getters are
// `public static` so they can be called from anywhere in contract code
// without weaving instance plumbing through the call graph.
//
// Each call charges one CONTEXT_READ helper-gas unit (see
// AVATA_CONTRACT_HELPER_CONTEXT_READ in include/avata/contract.h); cache the
// result in a local if the same value is needed multiple times in a hot
// loop.
//
// Determinism: every field returned here is derived deterministically from
// the inbound message, the WorkchainComputeContext, and ConfigParam 85.
// No wall-clock time, no host entropy, no validator-local state.
public final class Context {

  private Context() {
    // Non-instantiable; the contract surface is static-only.
  }

  // -----------------------------------------------------------------------
  // Self / receiver — the wc=3 account currently executing.
  // -----------------------------------------------------------------------

  public static Address contractAddress() {
    int workchain = nativeContractWorkchain();
    byte[] addr = nativeContractAddress();
    return new Address(workchain, addr);
  }

  // -----------------------------------------------------------------------
  // Caller — `src` of the inbound internal message.
  //
  // For first activation the caller is the deployer (the wc=3 sender that
  // emitted action_create_account). For subsequent calls it is whatever
  // account sent the int_msg_info that triggered this compute.
  //
  // External inbound messages have no authenticated caller; callerPresent()
  // is false in that case and caller() throws.
  // -----------------------------------------------------------------------

  public static boolean callerPresent() {
    return nativeCallerPresent();
  }

  public static Address caller() {
    if (! nativeCallerPresent()) {
      throw new ContractViolationError("inbound message has no caller");
    }
    int workchain = nativeCallerWorkchain();
    byte[] addr = nativeCallerAddress();
    return new Address(workchain, addr);
  }

  /** Reverts via Contract.revert(errorSignature) if `caller() != expected`. */
  public static void requireCaller(Address expected, String errorSignature) {
    if (expected == null || ! callerPresent()
        || ! caller().equals(expected)) {
      throw new ContractRevertException(errorSignature);
    }
  }

  // -----------------------------------------------------------------------
  // Attached value — TOMIS transferred with the inbound message.
  // Encoded as a 32-byte big-endian Uint256.
  // -----------------------------------------------------------------------

  public static Uint256 value() {
    byte[] raw = nativeValue();
    return Uint256.fromBytes(raw);
  }

  // -----------------------------------------------------------------------
  // Block / chain metadata.
  // -----------------------------------------------------------------------

  /** Masterchain block height that triggered this execution. */
  public static long blockNumber() {
    return nativeBlockNumber();
  }

  /** Unix-seconds block timestamp (the `now` field of the compute context). */
  public static long blockTimestamp() {
    return nativeBlockTimestamp();
  }

  /** Workchain-binding chain id from ConfigParam 85. */
  public static long chainId() {
    return nativeChainId();
  }

  /** True iff the runtime is in a static (read-only) call context. v1 has
   *  no static-call entry path, so this is always false today; the API is
   *  reserved so OpenZeppelin-style guards compile without conditional
   *  branches. */
  public static boolean isStaticCall() {
    return nativeIsStaticCall();
  }

  // -----------------------------------------------------------------------
  // Native bindings.
  // Each call charges AVATA_CONTRACT_HELPER_CONTEXT_READ; missing context
  // is surfaced as ContractViolationError before the JNI side returns.
  // -----------------------------------------------------------------------

  private static native int nativeContractWorkchain();

  private static native byte[] nativeContractAddress();

  private static native int nativeCallerWorkchain();

  private static native byte[] nativeCallerAddress();

  private static native boolean nativeCallerPresent();

  private static native byte[] nativeValue();

  private static native long nativeBlockNumber();

  private static native long nativeBlockTimestamp();

  private static native long nativeChainId();

  private static native boolean nativeIsStaticCall();
}
