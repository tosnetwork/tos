import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.StringWriter;
import java.io.Writer;

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

  private static void expectIndexOutOfBounds(Runnable r) {
    try {
      r.run();
      throw new RuntimeException("expected bounds exception");
    } catch (IndexOutOfBoundsException expected) {
    }
  }

  private static void throwUnchecked(IOException e) {
    throw new RuntimeException(e);
  }

  private static void testWriter() throws Exception {
    StringWriter writer = new StringWriter();
    writer.write("abcdef", 2, 3);
    expect("cde".equals(writer.toString()));

    expectIndexOutOfBounds(new Runnable() {
      public void run() {
        try {
          new StringWriter().write("abc", 1, Integer.MAX_VALUE);
        } catch (IOException e) {
          throwUnchecked(e);
        }
      }
    });

    expectIndexOutOfBounds(new Runnable() {
      public void run() {
        try {
          new StringWriter().write("abc", 1, -1);
        } catch (IOException e) {
          throwUnchecked(e);
        }
      }
    });

    CharSequence sequence = new CharSequence() {
      private final String value = "abcd";

      public int length() {
        return value.length();
      }

      public char charAt(int index) {
        return value.charAt(index);
      }

      public CharSequence subSequence(int start, int end) {
        return value.subSequence(start, end);
      }

      public String toString() {
        return value;
      }
    };

    writer = new StringWriter();
    writer.append(sequence, 1, 3);
    expect("bc".equals(writer.toString()));

    writer = new StringWriter();
    writer.append(null);
    expect("null".equals(writer.toString()));

    writer = new StringWriter();
    writer.append(null, 1, 3);
    expect("ul".equals(writer.toString()));

    final Writer finalWriter = new StringWriter();
    expectIndexOutOfBounds(new Runnable() {
      public void run() {
        try {
          finalWriter.append("abc", 2, 1);
        } catch (IOException e) {
          throwUnchecked(e);
        }
      }
    });
  }

  public static void main(String[] args) throws Exception {
    testWriter();

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
