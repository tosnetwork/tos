import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.IOException;
import java.io.OutputStream;

public class Streams {
  private static void expect(boolean v) {
    if (! v) throw new RuntimeException();
  }

  private static void expectOutOfBounds(Runnable r) {
    try {
      r.run();
      throw new RuntimeException("expected bounds exception");
    } catch (ArrayIndexOutOfBoundsException expected) {
    }
  }

  public static void main(String[] args) throws Exception {
    InputStream in = new InputStream() {
      public int read() {
        return -1;
      }
    };

    byte[] buffer = new byte[4];
    expect(in.read(buffer, 0, 0) == 0);
    expectOutOfBounds(new Runnable() {
      public void run() {
        try {
          InputStream in = new ByteArrayInputStream(new byte[4]);
          in.read(new byte[4], 2, Integer.MAX_VALUE);
        } catch (IOException e) {
          throw new RuntimeException(e);
        }
      }
    });

    OutputStream out = new OutputStream() {
      public void write(int c) {
      }
    };
    out.write(buffer, 0, 0);
    expectOutOfBounds(new Runnable() {
      public void run() {
        try {
          OutputStream out = new ByteArrayOutputStream();
          out.write(new byte[4], 2, Integer.MAX_VALUE);
        } catch (IOException e) {
          throw new RuntimeException(e);
        }
      }
    });
  }
}
