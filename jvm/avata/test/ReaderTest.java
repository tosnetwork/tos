import java.io.FilterReader;
import java.io.IOException;
import java.io.Reader;

public class ReaderTest {
  private static void expect(boolean value) {
    if (! value) {
      throw new RuntimeException();
    }
  }

  public static void main(String[] args) throws IOException {
    defaultReaderSkipAndReadyTest();
    filterReaderDelegationTest();
    filterReaderNullTest();
  }

  private static void defaultReaderSkipAndReadyTest() throws IOException {
    PlainReader reader = new PlainReader("abcd");
    expect(! reader.ready());
    expect(reader.skip(2) == 2);
    expect(reader.read() == 'c');
    expect(reader.skip(20) == 1);
    expect(reader.read() == -1);

    try {
      reader.skip(-1);
      throw new RuntimeException("Exception should have thrown");
    } catch (IllegalArgumentException e) {
      // expected
    }
  }

  private static void filterReaderDelegationTest() throws IOException {
    TrackingReader in = new TrackingReader("abcdef");
    PassThroughReader reader = new PassThroughReader(in);

    expect(reader.ready());
    expect(in.readyCalled);
    expect(reader.skip(2) == 2);
    expect(in.skipCalled);
    expect(reader.read() == 'c');

    reader.close();
    expect(in.closed);
  }

  private static void filterReaderNullTest() {
    try {
      new PassThroughReader(null);
      throw new RuntimeException("Exception should have thrown");
    } catch (NullPointerException e) {
      // expected
    }
  }

  private static class PassThroughReader extends FilterReader {
    PassThroughReader(Reader in) {
      super(in);
    }
  }

  private static class PlainReader extends Reader {
    protected final String input;
    protected int position;
    protected boolean closed;

    PlainReader(String input) {
      this.input = input;
    }

    public int read(char[] buffer, int offset, int length) throws IOException {
      if (closed) {
        throw new IOException("closed");
      }
      if (position >= input.length()) {
        return -1;
      }

      int count = Math.min(length, input.length() - position);
      input.getChars(position, position + count, buffer, offset);
      position += count;
      return count;
    }

    public void close() {
      closed = true;
    }
  }

  private static class TrackingReader extends PlainReader {
    boolean readyCalled;
    boolean skipCalled;

    TrackingReader(String input) {
      super(input);
    }

    public boolean ready() {
      readyCalled = true;
      return true;
    }

    public long skip(long count) throws IOException {
      skipCalled = true;
      return super.skip(count);
    }
  }
}
