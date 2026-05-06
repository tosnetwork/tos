public class CoreTrapProfile {
  private interface Thrower {
    void run();
  }

  private static void expectTrap(String name, Thrower thrower) {
    try {
      thrower.run();
    } catch (ContractViolationError expected) {
      return;
    }
    throw new RuntimeException("expected ContractViolationError: " + name);
  }

  private static void expectProperty(String key, String expected) {
    String actual = System.getProperty(key);
    if (expected == null ? actual != null : !expected.equals(actual)) {
      throw new RuntimeException("unexpected property " + key + ": " + actual);
    }
  }

  public static void main(String[] args) {
    expectProperty("line.separator", "\n");
    expectProperty("avata.builtins", null);
    expectProperty("java.class.path", null);

    expectTrap("Object.wait", new Thrower() {
      public void run() {
        try {
          new Object().wait(1);
        } catch (InterruptedException e) {
          throw new RuntimeException(e);
        }
      }
    });

    expectTrap("Object.notify", new Thrower() {
      public void run() {
        new Object().notify();
      }
    });
  }
}
