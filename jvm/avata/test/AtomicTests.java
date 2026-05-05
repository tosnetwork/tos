import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.atomic.AtomicReferenceArray;

// Rewritten to be single-threaded: verifies atomic read-modify-write
// semantics without requiring Thread.start() (unavailable in the consensus
// profile).  Concurrency stress is inherently untestable in the consensus
// VM; this suite covers correctness of each atomic operation.
public class AtomicTests {
  private static void expect(boolean v) {
    if (!v) throw new RuntimeException("assertion failed");
  }

  public static void main(String[] args) {
    testAtomicInteger();
    testAtomicLong();
    testAtomicBoolean();
    testAtomicReference();
    testAtomicReferenceArray();
  }

  private static void testAtomicInteger() {
    AtomicInteger a = new AtomicInteger(0);
    expect(a.get() == 0);
    expect(a.getAndIncrement() == 0);
    expect(a.get() == 1);
    expect(a.incrementAndGet() == 2);
    expect(a.getAndDecrement() == 2);
    expect(a.get() == 1);
    expect(a.decrementAndGet() == 0);
    expect(a.addAndGet(5) == 5);
    expect(a.getAndAdd(-3) == 5);
    expect(a.get() == 2);
    expect(a.compareAndSet(2, 42));
    expect(a.get() == 42);
    expect(!a.compareAndSet(0, 1));
    expect(a.get() == 42);
    a.set(10);
    expect(a.getAndSet(20) == 10);
    expect(a.get() == 20);
    expect(a.intValue() == 20);
    expect(a.longValue() == 20L);

    // Accumulate 1000 increments in a loop to verify no drift
    a.set(0);
    for (int i = 0; i < 1000; i++) a.incrementAndGet();
    expect(a.get() == 1000);
    a.set(0);
    for (int i = 0; i < 1000; i++) a.getAndIncrement();
    expect(a.get() == 1000);
    a.set(0);
    for (int i = 0; i < 1000; i++) a.decrementAndGet();
    expect(a.get() == -1000);
  }

  private static void testAtomicLong() {
    AtomicLong a = new AtomicLong(0L);
    expect(a.get() == 0L);
    expect(a.getAndIncrement() == 0L);
    expect(a.get() == 1L);
    expect(a.incrementAndGet() == 2L);
    expect(a.getAndDecrement() == 2L);
    expect(a.get() == 1L);
    expect(a.decrementAndGet() == 0L);
    expect(a.addAndGet(5L) == 5L);
    expect(a.getAndAdd(-3L) == 5L);
    expect(a.get() == 2L);
    expect(a.compareAndSet(2L, 42L));
    expect(a.get() == 42L);
    expect(!a.compareAndSet(0L, 1L));
    expect(a.get() == 42L);
    a.set(10L);
    expect(a.getAndSet(20L) == 10L);
    expect(a.get() == 20L);
    expect(a.longValue() == 20L);
    expect(a.intValue() == 20);

    a.set(0L);
    for (int i = 0; i < 1000; i++) a.incrementAndGet();
    expect(a.get() == 1000L);
  }

  private static void testAtomicBoolean() {
    AtomicBoolean a = new AtomicBoolean(false);
    expect(!a.get());
    expect(a.compareAndSet(false, true));
    expect(a.get());
    expect(!a.compareAndSet(false, true));
    expect(a.get());
    expect(a.getAndSet(false));
    expect(!a.get());
    a.set(true);
    expect(a.get());
  }

  private static void testAtomicReference() {
    AtomicReference<String> a = new AtomicReference<String>("hello");
    expect("hello".equals(a.get()));
    expect(a.compareAndSet("hello", "world"));
    expect("world".equals(a.get()));
    expect(!a.compareAndSet("hello", "foo"));
    expect("world".equals(a.get()));
    String old = a.getAndSet("bar");
    expect("world".equals(old));
    expect("bar".equals(a.get()));

    // Null handling
    a.set(null);
    expect(a.get() == null);
    expect(a.compareAndSet(null, "x"));
    expect("x".equals(a.get()));

    // Counter via CAS loop (simulates what concurrent clients would do)
    AtomicReference<Integer> counter = new AtomicReference<Integer>(0);
    for (int i = 0; i < 1000; i++) {
      Integer cur;
      do {
        cur = counter.get();
      } while (!counter.compareAndSet(cur, cur + 1));
    }
    expect(counter.get() == 1000);
  }

  private static void testAtomicReferenceArray() {
    AtomicReferenceArray<String> a = new AtomicReferenceArray<String>(3);
    expect(a.length() == 3);
    expect(a.get(0) == null);
    a.set(0, "x");
    expect("x".equals(a.get(0)));
    expect(a.compareAndSet(0, "x", "y"));
    expect("y".equals(a.get(0)));
    expect(!a.compareAndSet(0, "x", "z"));
    expect("y".equals(a.get(0)));
    String old = a.getAndSet(1, "hello");
    expect(old == null);
    expect("hello".equals(a.get(1)));
  }
}
