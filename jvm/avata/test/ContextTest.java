// Standalone-runner sanity check for java.lang.Context.
//
// The Avata test harness runs without a workchain runtime, so no
// AvataContractContext is installed.  Every Context getter must trip a
// deterministic ContractViolationError instead of silently returning
// garbage — that's the property this test pins.  The "happy path" is
// covered by C++ tests under crypto/test/test-workchain-execution-registry.cpp
// which install a real AvataContractContext through the workchain
// dispatch path.
public class ContextTest {
  public static void main(String[] args) {
    expectViolation("contractAddress", new Runnable() {
      public void run() { Context.contractAddress(); }
    });
    expectViolation("callerPresent", new Runnable() {
      public void run() { Context.callerPresent(); }
    });
    expectViolation("caller", new Runnable() {
      public void run() { Context.caller(); }
    });
    expectViolation("value", new Runnable() {
      public void run() { Context.value(); }
    });
    expectViolation("blockNumber", new Runnable() {
      public void run() { Context.blockNumber(); }
    });
    expectViolation("blockTimestamp", new Runnable() {
      public void run() { Context.blockTimestamp(); }
    });
    expectViolation("chainId", new Runnable() {
      public void run() { Context.chainId(); }
    });
    expectViolation("isStaticCall", new Runnable() {
      public void run() { Context.isStaticCall(); }
    });

    System.out.println("ContextTest: all getters trap without context");
  }

  private static void expectViolation(String name, Runnable r) {
    try {
      r.run();
    } catch (ContractViolationError e) {
      return;
    } catch (Throwable t) {
      throw new RuntimeException(
          "Context." + name + " threw wrong exception: " + t.getClass());
    }
    throw new RuntimeException(
        "Context." + name + " did not trap without an installed context");
  }
}
