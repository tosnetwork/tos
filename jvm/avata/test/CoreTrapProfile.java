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

  public static void main(String[] args) {
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
