package java.lang;

public class Pausable extends Contract {
  public static final String ENFORCED_PAUSE = "EnforcedPause()";
  public static final String EXPECTED_PAUSE = "ExpectedPause()";

  private boolean paused;

  public final boolean paused() {
    return paused;
  }

  public final void requireNotPaused() {
    if (paused) {
      revert(ENFORCED_PAUSE);
    }
  }

  public final void requirePaused() {
    if (! paused) {
      revert(EXPECTED_PAUSE);
    }
  }

  public void pause(Address caller) {
    requireNotPaused();
    paused = true;
  }

  public void unpause(Address caller) {
    requirePaused();
    paused = false;
  }
}
