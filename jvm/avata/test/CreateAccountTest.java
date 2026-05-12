// Standalone-runner sanity check for java.lang.System.createAccount.
//
// The standalone Avata test harness installs no AvataMessageHost
// `createAccount` callback, so the JNI bridge must trap deterministically
// with ContractViolationError after charging the gas cost.  Argument
// validation runs in pure Java before the host is consulted.
public class CreateAccountTest {
  public static void main(String[] args) {
    nullArgumentsRejected();
    emptyStateInitRejected();
    validInputTrapsWithoutHost();
    System.out.println(
        "CreateAccountTest: validation + missing-host trap ok");
  }

  private static void nullArgumentsRejected() {
    Address dest = sampleAddress();
    Uint256 value = Uint256.ZERO;
    byte[] stateInit = new byte[] { 0x01, 0x02, 0x03 };

    expect(NullPointerException.class, new Runnable() {
      public void run() {
        System.createAccount(null, stateInit, value, new byte[0]);
      }
    }, "createAccount(null, stateInit, value, body)");

    expect(NullPointerException.class, new Runnable() {
      public void run() {
        System.createAccount(dest, null, value, new byte[0]);
      }
    }, "createAccount(dest, null, value, body)");

    expect(NullPointerException.class, new Runnable() {
      public void run() {
        System.createAccount(dest, stateInit, null, new byte[0]);
      }
    }, "createAccount(dest, stateInit, null, body)");

    expect(NullPointerException.class, new Runnable() {
      public void run() {
        System.createAccount(dest, stateInit, value, null);
      }
    }, "createAccount(dest, stateInit, value, null)");
  }

  private static void emptyStateInitRejected() {
    Address dest = sampleAddress();
    Uint256 value = Uint256.ZERO;
    expect(IllegalArgumentException.class, new Runnable() {
      public void run() {
        System.createAccount(dest, new byte[0], value, new byte[0]);
      }
    }, "createAccount with empty stateInit");
  }

  private static void validInputTrapsWithoutHost() {
    Address dest = sampleAddress();
    Uint256 value = Uint256.valueOf(1);
    byte[] stateInit = new byte[] { (byte) 0xb5, (byte) 0xee, (byte) 0x9c };
    expect(ContractViolationError.class, new Runnable() {
      public void run() {
        System.createAccount(dest, stateInit, value, new byte[] { 1, 2 });
      }
    }, "createAccount without host");
  }

  private static Address sampleAddress() {
    byte[] addr = new byte[32];
    addr[31] = 0x42;
    return new Address(3, addr);
  }

  private static void expect(Class<? extends Throwable> expectedClass,
                             Runnable r, String label) {
    try {
      r.run();
    } catch (Throwable t) {
      if (expectedClass.isInstance(t)) {
        return;
      }
      throw new RuntimeException(
          label + " threw " + t.getClass() + " expected " + expectedClass);
    }
    throw new RuntimeException(
        label + " did not throw (expected " + expectedClass + ")");
  }
}
