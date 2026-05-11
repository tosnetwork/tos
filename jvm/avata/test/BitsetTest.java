import java.util.BitSet;

public class BitsetTest {

  public static void main(String[] args) {
    BitSet bits = new BitSet(16);
    bits.set(5);
    bits.set(1);
    
    BitSet other = new BitSet(16);
    other.set(5);
    
    assertTrue("bit 1 is set", bits.get(1));
    assertTrue("bit 5 is set", bits.get(5));
    assertTrue("bit 0 is not set", !bits.get(0));
    assertTrue("bit 16 is not set", !bits.get(16));
    assertCardinality(bits, 2);
    
    bits.and(other);
    
    assertTrue("bit 5 is set", bits.get(5));
    assertTrue("bit 1 is not set", !bits.get(1));
    assertCardinality(bits, 1);
    
    bits.set(100);
    
    assertTrue("bit 100 is set", bits.get(100));
    assertTrue("bit 101 is not set", !bits.get(101));
    assertCardinality(bits, 2);
    
    other.set(101);
    
    bits.or(other);
    
    assertTrue("bit 101 is set", bits.get(101));
    
    assertEquals("first bit is 5", 5, bits.nextSetBit(0));
    assertEquals("first bit is 5 from 3", 5, bits.nextSetBit(4));
    assertEquals("first bit is 5 from 5", 5, bits.nextSetBit(5));
    assertEquals("second bit is 100", 100, bits.nextSetBit(6));
    assertEquals("second bit is 100 from 100", 100, bits.nextSetBit(100));
    assertEquals("third bit is 101", 101, bits.nextSetBit(101));
    assertEquals("there is no 4th bit", -1, bits.nextSetBit(102));
    assertCardinality(bits, 3);
    
    assertEquals("first empty bit is 0", 0, bits.nextClearBit(0));
    assertEquals("after 5, 6 is empty", 6, bits.nextClearBit(5));
    assertEquals("after 100, 102 is empty", 102, bits.nextClearBit(100));
    
    testFlip();
    testClear();
    testJdkCompatibleEdges();

    BitSet expandingSet = new BitSet();
    //should force us to have 3 partitions.
    expandingSet.set(128);
  }
  
  private static void testFlip() {
    /* simple case */
    BitSet bitset = new BitSet();
    bitset.set(0);
    bitset.flip(0, 0);
    assertTrue("Should not be flipped with 0 length range", bitset.get(0));
    bitset.flip(0, 1);
    assertTrue("Should be false with range of one", !bitset.get(0));
    bitset.flip(0);
    assertTrue("Should be true again", bitset.get(0));
    
    /* need to grow */
    bitset.flip(1000);
    assertTrue("1000 should be true", bitset.get(1000));
    assertTrue("1001 should be false", !bitset.get(1001));
    assertTrue("999 should be false", !bitset.get(999));
    
    /* Range over 2 segments */
    bitset.flip(60, 70);
    assertTrue("59 should be false", !bitset.get(59));
    for (int i=60; i < 70; ++i) {
      assertTrue(i + " should be true", bitset.get(i));
    }
    assertTrue("70 should be false", !bitset.get(70));
  }

  private static void testClear() {
    BitSet bitset = new BitSet();
    bitset.set(0, 20);
    assertCardinality(bitset, 20);

    bitset.clear(1);
    assertTrue("bit 1 should be 0", !bitset.get(1));
    assertCardinality(bitset, 19);

    bitset.clear(0, 3);
    assertTrue("bit 0 should be 0", !bitset.get(0));
    assertTrue("bit 1 should be 0", !bitset.get(1));
    assertTrue("bit 2 should be 0", !bitset.get(2));
    assertTrue("bit 3 should be 1", bitset.get(3));
    assertCardinality(bitset, 17);

    bitset = new BitSet(70);
    bitset.flip(0, 65);
    for (int i=0; i < 65; ++i) {
      assertTrue("bit " + i + " should be set", bitset.get(i));
    }
    assertTrue("bit 65 should not be set", !bitset.get(65));
  }

  private static void testJdkCompatibleEdges() {
    BitSet bitset = new BitSet();
    assertEquals("empty length", 0, bitset.length());
    assertEquals("empty next set bit", -1, bitset.nextSetBit(0));
    assertEquals("empty next clear bit", 0, bitset.nextClearBit(0));

    bitset.set(0);
    assertEquals("one bit length", 1, bitset.length());
    assertEquals("clear bit after set", 1, bitset.nextClearBit(0));

    bitset.set(130);
    assertEquals("high bit length", 131, bitset.length());
    bitset.clear(130);
    assertEquals("length shrinks after clear", 1, bitset.length());

    bitset.clear(1, 1000);
    assertEquals("clear beyond storage is allowed", 1, bitset.length());
    bitset.clear();
    assertTrue("clear all empties set", bitset.isEmpty());

    BitSet left = new BitSet();
    BitSet right = new BitSet();
    right.set(128);
    assertTrue("different sized non-overlap does not intersect", !left.intersects(right));
    left.set(128);
    assertTrue("different sized overlap intersects", left.intersects(right));

    expectIndexOutOfBounds(new Runnable() {
      public void run() {
        new BitSet().get(-1);
      }
    });
    expectIndexOutOfBounds(new Runnable() {
      public void run() {
        new BitSet().set(2, 1);
      }
    });
    expectIndexOutOfBounds(new Runnable() {
      public void run() {
        new BitSet().nextSetBit(-1);
      }
    });
  }

  private static void expectIndexOutOfBounds(Runnable runnable) {
    try {
      runnable.run();
      throw new RuntimeException("Expected IndexOutOfBoundsException");
    } catch (IndexOutOfBoundsException expected) {
      // expected
    }
  }
  
  static void assertTrue(String msg, boolean flag) {
    if (flag) {
      System.out.println(msg + " : OK.");
    } else {
      throw new RuntimeException("Error:"+msg);
    }
  }

  static void assertEquals(String msg, int expected, int actual) {
    if (expected==actual) {
      System.out.println(msg + " : OK. ["+actual+']');
    } else {
      throw new RuntimeException("Error:"+msg+" expected:"+expected+", actual:"+actual);
    }
  }
  
  static void assertCardinality(BitSet set, int expectedCardinality) {
    assertEquals("Checking cardinality", expectedCardinality, set.cardinality());
  }
  
}
