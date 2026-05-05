import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.CharBuffer;
import java.nio.BufferUnderflowException;
import java.nio.BufferOverflowException;
import java.nio.ReadOnlyBufferException;
import static avata.testing.Asserts.*;

public class Buffers {
  static {
    System.loadLibrary("test");
  }
  
  private static void testArrays(Factory factory1, Factory factory2) {
    final int size = 64;
    ByteBuffer b1 = factory1.allocate(size);
    ByteBuffer b2 = factory2.allocate(size);
    
    String s = "1234567890abcdefghijklmnopqrstuvwxyz";
    b1.put(s.getBytes());
    b1.flip();
    byte[] ba = new byte[s.length()];
    b1.get(ba);
    assertEquals(s, new String(ba));
    b1.position(0);
    b2.put(b1);
    b2.flip();
    b2.get(ba);
    assertEquals(s, new String(ba));
    b1.position(0);
    b2.position(0);
    b1.limit(b1.capacity());
    b2.limit(b2.capacity());
    b1.put(s.getBytes(), 4, 5);
    b1.flip();
    ba = new byte[5];
    b1.get(ba);
    assertEquals(s.substring(4, 9), new String(ba));
  }

  private static void testPrimativeGetAndSet(Factory factory1, Factory factory2) {
    { final int size = 64;
      ByteBuffer b1 = factory1.allocate(size);
      try {

        for (int i = 0; i < size; ++i)
          b1.put(i, (byte) 42);

        for (int i = 0; i < size; ++i)
          assertEquals(b1.get(i), 42);
        
        for (int i = 0; i < size/4; i++) 
          b1.putFloat(i*4, (float) 19.12);
        
        for (int i = 0; i < size/4; i++) 
          assertEquals(b1.getFloat(i*4), (float) 19.12);

        ByteBuffer b3 = b1.duplicate();
        for (int i = 0; i < size/4; i++)
          assertEquals(b3.getFloat(), (float) 19.12);
        assertEquals(64, b3.position());
        
        for (int i = 0; i < size/8; i++) 
          b1.putDouble(i*8, (double) 19.12);
        
        for (int i = 0; i < size/8; i++)
          assertEquals(b1.getDouble(i*8), (double) 19.12);
        
        b3.position(0);
        
        for (int i = 0; i < size/8; i++)
          assertEquals(b3.getDouble(i*8), (double) 19.12);

        for (int i = 0; i < size / 2; ++i)
          b1.putShort(i * 2, (short) -12345);

        for (int i = 0; i < size / 2; ++i)
          assertEquals(b1.getShort(i * 2), -12345);

        for (int i = 0; i < size / 4; ++i)
          b1.putInt(i * 4, 0x12345678);

        for (int i = 0; i < size / 4; ++i)
          assertEquals(b1.getInt(i * 4), 0x12345678);

        for (int i = 0; i < size / 8; ++i)
          b1.putLong(i * 8, 0x1234567890ABCDEFL);

        for (int i = 0; i < size / 8; ++i)
          assertEquals(b1.getLong(i * 8),  0x1234567890ABCDEFL);

        ByteBuffer b2 = factory2.allocate(size);
        try {
          b2.put(b1);

          for (int i = 0; i < size / 8; ++i)
            assertTrue(b2.getLong(i * 8) ==  0x1234567890ABCDEFL);

        } finally {
          factory2.dispose(b2);
        }
      } finally {
        factory1.dispose(b1);
      }
    }
  }

  private static void expectIndexOutOfBounds(Runnable r) {
    try {
      r.run();
      assertTrue(false);
    } catch (IndexOutOfBoundsException expected) {
      // ok
    }
  }

  private static void expectIllegalArgument(Runnable r) {
    try {
      r.run();
      assertTrue(false);
    } catch (IllegalArgumentException expected) {
      // ok
    }
  }

  private static void expectReadOnlyBuffer(Runnable r) {
    try {
      r.run();
      assertTrue(false);
    } catch (ReadOnlyBufferException expected) {
      // ok
    }
  }

  private static void testBounds() {
    final byte[] array = new byte[8];

    expectIndexOutOfBounds(new Runnable() {
      public void run() {
        ByteBuffer.wrap(array, -1, 1);
      }
    });

    expectIndexOutOfBounds(new Runnable() {
      public void run() {
        ByteBuffer.wrap(array).put(array, 2, Integer.MAX_VALUE);
      }
    });

    expectIndexOutOfBounds(new Runnable() {
      public void run() {
        ByteBuffer.wrap(array).get(array, 2, Integer.MAX_VALUE);
      }
    });

    expectIllegalArgument(new Runnable() {
      public void run() {
        ByteBuffer.wrap(array).position(-1);
      }
    });

    expectIllegalArgument(new Runnable() {
      public void run() {
        ByteBuffer.wrap(array).limit(9);
      }
    });

    ByteBuffer direct = ByteBuffer.allocateDirect(8);
    direct.put(new byte[] {1, 2, 3, 4});
    direct.flip();
    byte[] out = new byte[2];
    direct.get(out, 0, 2);
    assertEquals(2, direct.position());
  }

  private static void testByteOrder() {
    ByteBuffer buffer = ByteBuffer.allocate(16);
    assertEquals(ByteOrder.BIG_ENDIAN, buffer.order());

    buffer.order(ByteOrder.LITTLE_ENDIAN);
    assertEquals(ByteOrder.LITTLE_ENDIAN, buffer.order());
    buffer.putInt(0x01020304);
    buffer.putShort((short) 0x0506);
    buffer.putLong(0x0708090A0B0C0D0EL);
    buffer.flip();

    assertEquals((byte) 0x04, buffer.get());
    assertEquals((byte) 0x03, buffer.get());
    assertEquals((byte) 0x02, buffer.get());
    assertEquals((byte) 0x01, buffer.get());
    assertEquals((byte) 0x06, buffer.get());
    assertEquals((byte) 0x05, buffer.get());
    assertEquals(0x0708090A0B0C0D0EL, buffer.getLong());

    buffer.rewind();
    assertEquals(0x01020304, buffer.getInt());
    assertEquals((short) 0x0506, buffer.getShort());

    buffer.order(ByteOrder.BIG_ENDIAN);
    buffer.rewind();
    assertEquals(0x04030201, buffer.getInt());

    assertEquals(ByteOrder.BIG_ENDIAN,
                 buffer.order(ByteOrder.LITTLE_ENDIAN).duplicate().order());
    assertEquals(ByteOrder.BIG_ENDIAN, buffer.slice().order());
    assertEquals(ByteOrder.BIG_ENDIAN, buffer.asReadOnlyBuffer().order());

    try {
      buffer.order(null);
      assertTrue(false);
    } catch (NullPointerException e) {
      // ok
    }
  }

  private static void testArrayBackedViews() {
    byte[] bytes = new byte[] { 1, 2, 3, 4 };
    ByteBuffer buffer = ByteBuffer.wrap(bytes);
    buffer.position(1);
    buffer.limit(3);

    ByteBuffer slice = buffer.slice();
    assertTrue(! slice.isReadOnly());
    assertTrue(slice.hasArray());
    assertEquals(1, slice.arrayOffset());
    assertEquals(2, slice.capacity());
    slice.put(0, (byte) 9);
    assertEquals((byte) 9, bytes[1]);

    final ByteBuffer readOnly = buffer.asReadOnlyBuffer();
    assertTrue(readOnly.isReadOnly());
    assertTrue(! readOnly.hasArray());
    expectReadOnlyBuffer(new Runnable() {
      public void run() {
        readOnly.array();
      }
    });
    expectReadOnlyBuffer(new Runnable() {
      public void run() {
        readOnly.arrayOffset();
      }
    });

    final ByteBuffer readOnlySlice = readOnly.slice();
    assertTrue(readOnlySlice.isReadOnly());
    assertTrue(! readOnlySlice.hasArray());
    expectReadOnlyBuffer(new Runnable() {
      public void run() {
        readOnlySlice.put((byte) 1);
      }
    });

    ByteBuffer readOnlyDuplicate = readOnly.duplicate();
    assertTrue(readOnlyDuplicate.isReadOnly());
    assertTrue(! readOnlyDuplicate.hasArray());

    char[] chars = new char[] { 'a', 'b', 'c' };
    CharBuffer charBuffer = CharBuffer.wrap(chars);
    charBuffer.position(1);

    CharBuffer charSlice = charBuffer.slice();
    assertTrue(! charSlice.isReadOnly());
    assertTrue(charSlice.hasArray());
    assertEquals(1, charSlice.arrayOffset());
    assertEquals(2, charSlice.capacity());
    charSlice.put(0, 'z');
    assertEquals((int) 'z', (int) chars[1]);

    final CharBuffer readOnlyChars = charBuffer.asReadOnlyBuffer();
    assertTrue(readOnlyChars.isReadOnly());
    assertTrue(! readOnlyChars.hasArray());
    expectReadOnlyBuffer(new Runnable() {
      public void run() {
        readOnlyChars.array();
      }
    });
    expectReadOnlyBuffer(new Runnable() {
      public void run() {
        readOnlyChars.arrayOffset();
      }
    });

    final CharBuffer readOnlyCharSlice = readOnlyChars.slice();
    assertTrue(readOnlyCharSlice.isReadOnly());
    assertTrue(! readOnlyCharSlice.hasArray());
    expectReadOnlyBuffer(new Runnable() {
      public void run() {
        readOnlyCharSlice.put('x');
      }
    });
  }

  private static native ByteBuffer allocateNative(int capacity);

  private static native void freeNative(ByteBuffer b);

  public static void main(String[] args) throws Exception {
    Factory array = new Factory() {
        public ByteBuffer allocate(int capacity) {
          return ByteBuffer.allocate(capacity);
        }

        public void dispose(ByteBuffer b) {
          // ignore
        }
      };

    Factory direct = new Factory() {
        public ByteBuffer allocate(int capacity) {
          return ByteBuffer.allocateDirect(capacity);
        }

        public void dispose(ByteBuffer b) {
          // ignore
        }
      };

    Factory native_ = new Factory() {
        public ByteBuffer allocate(int capacity) {
          return allocateNative(capacity);
        }

        public void dispose(ByteBuffer b) {
          freeNative(b);
        }
      };

    testPrimativeGetAndSet(array, array);
    testArrays(array, array);
    testPrimativeGetAndSet(array, direct);
    testArrays(array, direct);
    testPrimativeGetAndSet(array, native_);
    testArrays(array, native_);

    testPrimativeGetAndSet(direct, array);
    testArrays(direct, array);
    testPrimativeGetAndSet(direct, direct);
    testArrays(direct, direct);
    testPrimativeGetAndSet(direct, native_);
    testArrays(direct, native_);

    testPrimativeGetAndSet(native_, array);
    testArrays(native_, array);
    testPrimativeGetAndSet(native_, direct);
    testArrays(native_, direct);
    testPrimativeGetAndSet(native_, native_);
    testArrays(native_, native_);
    testBounds();
    testByteOrder();
    testArrayBackedViews();

    try {
      ByteBuffer.allocate(1).getInt();
      assertTrue(false);
    } catch (BufferUnderflowException e) {
      // cool
    }

    try {
      ByteBuffer.allocate(1).getInt(0);
      assertTrue(false);
    } catch (IndexOutOfBoundsException e) {
      // cool
    }

    try {
      ByteBuffer.allocate(1).putInt(1);
      assertTrue(false);
    } catch (BufferOverflowException e) {
      // cool
    }

    try {
      ByteBuffer.allocate(1).putInt(0, 1);
      assertTrue(false);
    } catch (IndexOutOfBoundsException e) {
      // cool
    }
  }

  private interface Factory {
    public ByteBuffer allocate(int capacity);

    public void dispose(ByteBuffer b);
  }
}
