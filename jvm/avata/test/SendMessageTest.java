// Standalone-runner sanity check for java.lang.System.sendMessage.
//
// The standalone Avata test harness installs no AvataMessageHost, so the
// JNI bridge must trap deterministically with ContractViolationError.
// Argument validation (null checks, byte-length checks for the destination
// + value) runs in pure Java before the host is consulted, so the
// IllegalArgumentException / NullPointerException paths can be verified
// without any host.
public class SendMessageTest {
  public static void main(String[] args) {
    nullArgumentsRejected();
    validInputTrapsWithoutHost();
    System.out.println("SendMessageTest: validation + missing-host trap ok");
  }

  private static void nullArgumentsRejected() {
    Address dest = sampleAddress();
    Uint256 value = Uint256.ZERO;

    expect(NullPointerException.class, new Runnable() {
      public void run() { System.sendMessage(null, value, new byte[0]); }
    }, "sendMessage(null, value, body)");

    expect(NullPointerException.class, new Runnable() {
      public void run() { System.sendMessage(dest, null, new byte[0]); }
    }, "sendMessage(dest, null, body)");

    expect(NullPointerException.class, new Runnable() {
      public void run() { System.sendMessage(dest, value, null); }
    }, "sendMessage(dest, value, null)");
  }

  private static void validInputTrapsWithoutHost() {
    Address dest = sampleAddress();
    Uint256 value = Uint256.valueOf(1);
    expect(ContractViolationError.class, new Runnable() {
      public void run() { System.sendMessage(dest, value, new byte[] { 1, 2 }); }
    }, "sendMessage without host");
  }

  private static Address sampleAddress() {
    byte[] addr = new byte[32];
    addr[31] = 0x42;
    return new Address(0, addr);
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
