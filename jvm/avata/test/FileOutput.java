import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;

public class FileOutput {
  private static void expect(boolean v) {
    if (! v) throw new RuntimeException();
  }

  private interface Action {
    void run() throws IOException;
  }

  private static void expectFileNotFound(Action action) throws IOException {
    try {
      action.run();
      throw new RuntimeException("expected FileNotFoundException");
    } catch (FileNotFoundException expected) {
    }
  }

  private static void test(boolean appendFirst) throws IOException {
    try {
      FileOutputStream f = new FileOutputStream("test.txt", appendFirst);
      f.write("Hello world!\n".getBytes());
      f.close();
      
      FileOutputStream f2 = new FileOutputStream("test.txt", true);
      f2.write("Hello world again!".getBytes());
      f2.close();
      
      FileInputStream in = new FileInputStream("test.txt");
      byte[] buffer = new byte[256];
      int c;
      int offset = 0;
      expect(in.read(buffer, 0, 0) == 0);
      while ((c = in.read(buffer, offset, buffer.length - offset)) != -1) {
        offset += c;
      }
      in.close();

      if (! "Hello world!\nHello world again!".equals
          (new String(buffer, 0, offset)))
      {
        throw new RuntimeException();
      }
    } finally {
      expect(new File("test.txt").delete());
    }
  }

  private static void testRandomAccessFile() throws IOException {
    final File file = new File("random-access-test.txt");
    try {
      expectFileNotFound(new Action() {
        public void run() throws IOException {
          new RandomAccessFile(new File("."), "r");
        }
      });

      expectFileNotFound(new Action() {
        public void run() throws IOException {
          new RandomAccessFile(new File("."), "rw");
        }
      });

      RandomAccessFile raf = new RandomAccessFile(file, "rwd");
      raf.write(new byte[] { 1, 2, 3, 4 }, 0, 4);
      expect(raf.length() == 4);

      raf.seek(1);
      byte[] pair = new byte[2];
      expect(raf.read(pair, 0, pair.length) == 2);
      expect(pair[0] == 2 && pair[1] == 3);

      raf.seek(100);
      expect(raf.getFilePointer() == 100);
      raf.writeByte(5);
      expect(raf.length() == 101);

      raf.setLength(4);
      expect(raf.length() == 4);
      expect(raf.getFilePointer() == 4);
      expect(raf.read() == -1);
      try {
        raf.readFully(new byte[1]);
        throw new RuntimeException("expected EOFException");
      } catch (EOFException expected) {
      }

      raf.setLength(0);
      raf.seek(0);
      raf.writeInt(0x010203ff);
      raf.writeFloat(3.5f);
      raf.writeDouble(4.25d);
      raf.seek(0);
      expect(raf.readInt() == 0x010203ff);
      expect(raf.readFloat() == 3.5f);
      expect(raf.readDouble() == 4.25d);

      byte[] backing = new byte[] { 9, 9, 9, 9, 9 };
      ByteBuffer readBuffer = ByteBuffer.wrap(backing, 1, 3);
      expect(raf.getChannel().read(readBuffer, 1) == 3);
      expect(readBuffer.position() == 3);
      expect(backing[0] == 9 && backing[1] == 2 && backing[2] == 3
             && backing[3] == (byte)0xff && backing[4] == 9);

      byte[] source = new byte[] { 0, 7, 8, 9, 0 };
      ByteBuffer writeBuffer = ByteBuffer.wrap(source, 1, 3);
      expect(raf.getChannel().write(writeBuffer, 2) == 3);
      expect(writeBuffer.position() == 3);
      raf.seek(2);
      byte[] overwritten = new byte[3];
      raf.readFully(overwritten);
      expect(overwritten[0] == 7 && overwritten[1] == 8
             && overwritten[2] == 9);

      long beforeSkip = raf.getFilePointer();
      long fileLength = raf.length();
      expect(raf.skipBytes(1000) == (int)(fileLength - beforeSkip));
      raf.close();

      RandomAccessFile readonly = new RandomAccessFile(file, "r");
      readonly.seek(1000);
      expect(readonly.read() == -1);
      readonly.close();
    } finally {
      if (file.exists()) expect(file.delete());
    }
  }

  public static void main(String[] args) throws IOException {
    expect(new File("nonexistent-file").length() == 0);

    expectFileNotFound(new Action() {
      public void run() throws IOException {
        new FileInputStream(new File("."));
      }
    });

    expectFileNotFound(new Action() {
      public void run() throws IOException {
        new FileOutputStream(new File("."));
      }
    });

    test(false);
    test(true);
    testRandomAccessFile();

    final File boundsFile = new File("bounds-test.txt");
    try {
      FileOutputStream out = new FileOutputStream(boundsFile);
      out.write(new byte[] {1, 2, 3, 4}, 0, 4);
      out.write(new byte[] {1, 2, 3, 4}, 0, 0);
      out.close();

      final byte[] buffer = new byte[4];
      FileInputStream in = new FileInputStream(boundsFile);
      try {
        in.read(buffer, -1, 1);
        throw new RuntimeException("expected bounds exception");
      } catch (ArrayIndexOutOfBoundsException expected) {
      } finally {
        in.close();
      }

      out = new FileOutputStream(boundsFile);
      try {
        out.write(buffer, 2, Integer.MAX_VALUE);
        throw new RuntimeException("expected bounds exception");
      } catch (ArrayIndexOutOfBoundsException expected) {
      } finally {
        out.close();
      }
    } finally {
      expect(boundsFile.delete());
    }
  }

}
