package java.lang;

public class ReentrancyGuard extends Contract {
  public static final String REENTRANT_CALL =
      "ReentrancyGuardReentrantCall()";

  private static final int NOT_ENTERED = 1;
  private static final int ENTERED = 2;

  private int status = NOT_ENTERED;

  public final boolean entered() {
    return status == ENTERED;
  }

  public final void enter() {
    if (entered()) {
      revert(REENTRANT_CALL);
    }
    status = ENTERED;
  }

  public final void exit() {
    status = NOT_ENTERED;
  }
}
