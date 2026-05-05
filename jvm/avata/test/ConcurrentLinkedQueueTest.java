import java.util.Iterator;
import java.util.LinkedList;
import java.util.NoSuchElementException;
import java.util.concurrent.ConcurrentLinkedQueue;

public class ConcurrentLinkedQueueTest {
  private static void verify(boolean value) {
    if (! value) {
      throw new RuntimeException();
    }
  }

  public static void main(String[] args) {
    QueueHelper.sizeTest(new ConcurrentLinkedQueue<Object>());
    QueueHelper.isEmptyTest(new ConcurrentLinkedQueue<Object>());
    QueueHelper.addTest(new ConcurrentLinkedQueue<Object>());
    QueueHelper.addAllTest(new ConcurrentLinkedQueue<Object>());
    QueueHelper.elementTest(new ConcurrentLinkedQueue<Object>());
    QueueHelper.elementFail(new ConcurrentLinkedQueue<Object>());
    QueueHelper.removeEmptyFail(new ConcurrentLinkedQueue<Object>());
    QueueHelper.removeTest(new ConcurrentLinkedQueue<Object>());
    QueueHelper.containsTest(new ConcurrentLinkedQueue<Object>());
    QueueHelper.containsAllTest(new ConcurrentLinkedQueue<Object>());
    QueueHelper.removeObjectTest(new ConcurrentLinkedQueue<Object>());
    QueueHelper.removeAllTest(new ConcurrentLinkedQueue<Object>());
    QueueHelper.clearTest(new ConcurrentLinkedQueue<Object>());
    QueueHelper.toArrayTest(new ConcurrentLinkedQueue<Object>());

    nullElementTest();
    addAllEdgeTest();
    iteratorTest();
    removeBeforePollTest();
    removeAllDuplicateTest();
    typedToArrayTest();
  }

  private static void nullElementTest() {
    ConcurrentLinkedQueue<Object> queue = new ConcurrentLinkedQueue<Object>();

    try {
      queue.add(null);
      throw new RuntimeException("Exception should have thrown");
    } catch (NullPointerException e) {
      // expected
    }

    try {
      queue.offer(null);
      throw new RuntimeException("Exception should have thrown");
    } catch (NullPointerException e) {
      // expected
    }

    verify(queue.isEmpty());
    verify(! queue.contains(null));
    verify(! queue.remove(null));
  }

  private static void addAllEdgeTest() {
    ConcurrentLinkedQueue<String> queue = new ConcurrentLinkedQueue<String>();
    LinkedList<String> empty = new LinkedList<String>();
    verify(! queue.addAll(empty));

    try {
      queue.addAll(queue);
      throw new RuntimeException("Exception should have thrown");
    } catch (IllegalArgumentException e) {
      // expected
    }

    LinkedList<String> values = new LinkedList<String>();
    values.add("one");
    values.add(null);
    try {
      queue.addAll(values);
      throw new RuntimeException("Exception should have thrown");
    } catch (NullPointerException e) {
      // expected
    }

    verify(queue.isEmpty());
  }

  private static void iteratorTest() {
    ConcurrentLinkedQueue<String> queue = new ConcurrentLinkedQueue<String>();
    queue.add("one");
    queue.add("two");

    Iterator<String> iterator = queue.iterator();
    verify(iterator.hasNext());
    verify("one".equals(iterator.next()));
    iterator.remove();
    verify(! queue.contains("one"));
    verify("two".equals(queue.peek()));

    verify(iterator.hasNext());
    verify("two".equals(iterator.next()));
    iterator.remove();
    verify(queue.isEmpty());

    try {
      iterator.remove();
      throw new RuntimeException("Exception should have thrown");
    } catch (IllegalStateException e) {
      // expected
    }

    try {
      iterator.next();
      throw new RuntimeException("Exception should have thrown");
    } catch (NoSuchElementException e) {
      // expected
    }
  }

  private static void removeBeforePollTest() {
    ConcurrentLinkedQueue<String> queue = new ConcurrentLinkedQueue<String>();
    queue.add("one");
    queue.add("two");

    verify(queue.remove("one"));
    verify("two".equals(queue.peek()));
    verify("two".equals(queue.poll()));
    verify(queue.poll() == null);
  }

  private static void removeAllDuplicateTest() {
    ConcurrentLinkedQueue<String> queue = new ConcurrentLinkedQueue<String>();
    queue.add("drop");
    queue.add("keep");
    queue.add("drop");

    LinkedList<String> remove = new LinkedList<String>();
    remove.add("drop");

    verify(queue.removeAll(remove));
    verify(queue.size() == 1);
    verify("keep".equals(queue.poll()));
    verify(queue.isEmpty());
  }

  private static void typedToArrayTest() {
    ConcurrentLinkedQueue<String> queue = new ConcurrentLinkedQueue<String>();
    queue.add("one");
    queue.add("two");

    Object[] objects = queue.toArray();
    verify(objects.length == 2);
    verify("one".equals(objects[0]));
    verify("two".equals(objects[1]));

    String[] small = queue.toArray(new String[0]);
    verify(small.length == 2);
    verify("one".equals(small[0]));
    verify("two".equals(small[1]));

    String[] large = new String[3];
    String[] result = queue.toArray(large);
    verify(result == large);
    verify("one".equals(result[0]));
    verify("two".equals(result[1]));
    verify(result[2] == null);
  }
}
