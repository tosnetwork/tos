import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;

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
