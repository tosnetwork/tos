public class MonitorTest {
  private static void check(boolean cond, String msg) {
    if (!cond) throw new RuntimeException(msg);
  }

  // Case 1: basic synchronized block acquires and releases the monitor.
  private static int testBasicBlock() {
    Object lock = new Object();
    int result = 0;
    synchronized (lock) {
      result = 42;
    }
    return result;
  }

  // Case 2: reentrant — the same thread may re-enter a monitor it already holds.
  private static int testReentrant() {
    Object lock = new Object();
    int result = 0;
    synchronized (lock) {
      result += 1;
      synchronized (lock) {
        result += 10;
        synchronized (lock) {
          result += 100;
        }
      }
    }
    return result;
  }

  // Case 3: monitor is released even when an exception is thrown inside the block.
  // If monitorexit were not emitted on the exceptional path, a second synchronized
  // block on the same object would deadlock.
  private static boolean testExceptionReleasesMonitor() {
    Object lock = new Object();
    try {
      synchronized (lock) {
        throw new RuntimeException("expected");
      }
    } catch (RuntimeException e) {
      // monitor must have been released by this point
    }
    // acquiring the same monitor again must succeed without deadlock
    synchronized (lock) {
      return true;
    }
  }

  // Case 4: value written inside a synchronized block is visible outside it.
  private static String testValueVisible() {
    Object lock = new Object();
    String[] box = new String[1];
    synchronized (lock) {
      box[0] = "hello";
    }
    return box[0];
  }

  // Case 5: two different lock objects are independent (no cross-interference).
  private static int testTwoLocks() {
    Object a = new Object();
    Object b = new Object();
    int result = 0;
    synchronized (a) {
      result += 1;
      synchronized (b) {
        result += 10;
      }
      result += 100;
    }
    return result;
  }

  public static void main(String[] args) {
    check(testBasicBlock() == 42,
          "basic block: expected 42, got " + testBasicBlock());

    check(testReentrant() == 111,
          "reentrant: expected 111, got " + testReentrant());

    check(testExceptionReleasesMonitor(),
          "exception release: second acquire failed");

    check("hello".equals(testValueVisible()),
          "value visible: expected hello");

    check(testTwoLocks() == 111,
          "two locks: expected 111, got " + testTwoLocks());

    System.out.println("MonitorTest: all passed");
  }
}
