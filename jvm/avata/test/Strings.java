public class Strings {
  private static void expect(boolean v) {
    if (! v) throw new RuntimeException();
  }

  private interface Action {
    public void run() throws Exception;
  }

  private static void expectStringIndexOutOfBounds(Action action)
    throws Exception
  {
    try {
      action.run();
      throw new RuntimeException("expected StringIndexOutOfBoundsException");
    } catch (StringIndexOutOfBoundsException expected) {
    }
  }

  private static void expectArrayIndexOutOfBounds(Action action)
    throws Exception
  {
    try {
      action.run();
      throw new RuntimeException("expected ArrayIndexOutOfBoundsException");
    } catch (ArrayIndexOutOfBoundsException expected) {
    }
  }

  private static void expectNullPointer(Action action)
    throws Exception
  {
    try {
      action.run();
      throw new RuntimeException("expected NullPointerException");
    } catch (NullPointerException expected) {
    }
  }

  private static void expectUnsupported(Action action)
    throws Exception
  {
    try {
      action.run();
      throw new RuntimeException("expected UnsupportedOperationException");
    } catch (UnsupportedOperationException expected) {
    }
  }

  private static void expectUnsupportedEncoding(Action action)
    throws Exception
  {
    try {
      action.run();
      throw new RuntimeException("expected UnsupportedEncodingException");
    } catch (java.io.UnsupportedEncodingException expected) {
    }
  }

  private static boolean equal(Object a, Object b) {
    return a == b || (a != null && a.equals(b));
  }

  private static boolean arraysEqual(byte[] a, byte[] b) {
    if (a.length != b.length) {
      return false;
    }

    for (int i = 0; i < a.length; ++i) {
      if (a[i] != b[i]) {
        return false;
      }
    }

    return true;
  }

  private static byte[] append(byte[] a, byte[] b) {
    byte[] c = new byte[a.length + b.length];
    for (int i = 0; i < a.length; ++i) {
      c[i] = a[i];
    }
    for (int i = 0; i < b.length; ++i) {
      c[i + a.length] = b[i];
    }
    return c;
  }

  private static boolean arraysEqual(Object[] a, Object[] b) {
    if (a.length != b.length) {
      return false;
    }

    for (int i = 0; i < a.length; ++i) {
      if (! equal(a[i], b[i])) {
        return false;
      }
    }

    return true;
  }

  private static void testDecode(final boolean prematureEOS) throws Exception {
    java.io.Reader r = new java.io.InputStreamReader
      (new java.io.InputStream() {
          int state = 0;

          public int read() {
            throw new UnsupportedOperationException();
          }

          public int read(byte[] b, int offset, int length) {
            if (length == 0) return 0;

            switch (state) {
            case 0:
              b[offset] = (byte) 0xc2;
              state = 1;
              return 1;

            case 1:
              b[offset] = (byte) 0xae;
              state = 2;
              return 1;

            case 2:
              b[offset] = (byte) 0xea;
              state = 3;
              return 1;

            case 3:
              b[offset] = (byte) 0xba;
              state = prematureEOS ? 5 : 4;
              return 1;

            case 4:
              b[offset] = (byte) 0xaf;
              state = 5;
              return 1;

            case 5:
              return -1;

            default:
              throw new RuntimeException();
            }
          }
        }, "UTF-8");

    char[] buffer = new char[2];
    int offset = 0;
    while (offset < buffer.length) {
      int c = r.read(buffer, offset, buffer.length - offset);
      if (c == -1) break;
      offset += c;
    }

    expect(new String(buffer, 0, offset).equals
           (prematureEOS ? "\u00ae\ufffd" : "\u00ae\uaeaf"));
  }

  private static void testStringBounds() throws Exception {
    final byte[] oneByte = new byte[] { 97 };
    final char[] oneChar = new char[] { 'a' };

    expectStringIndexOutOfBounds(new Action() {
      public void run() {
        new String(oneByte, 1, Integer.MAX_VALUE);
      }
    });

    expectStringIndexOutOfBounds(new Action() {
      public void run() throws Exception {
        new String(oneByte, 0, Integer.MAX_VALUE, "UTF-8");
      }
    });

    expectStringIndexOutOfBounds(new Action() {
      public void run() {
        new String(oneByte, 0, 1, Integer.MAX_VALUE);
      }
    });

    expectStringIndexOutOfBounds(new Action() {
      public void run() {
        new String(oneChar, 1, Integer.MAX_VALUE);
      }
    });

    byte[] out = new byte[5];
    "abcdef".getBytes(2, 5, out, 1);
    expect(arraysEqual(out, new byte[] { 0, 99, 100, 101, 0 }));

    expectStringIndexOutOfBounds(new Action() {
      public void run() {
        "abc".getBytes(2, 1, new byte[1], 0);
      }
    });

    expectArrayIndexOutOfBounds(new Action() {
      public void run() {
        "abc".getBytes(1, 3, new byte[1], 0);
      }
    });

    char[] chars = new char[2];
    "abc".getChars(1, 3, chars, 0);
    expect(chars[0] == 'b' && chars[1] == 'c');

    expectStringIndexOutOfBounds(new Action() {
      public void run() {
        "abc".getChars(2, 1, new char[1], 0);
      }
    });
  }

  public static void main(String[] args) throws Exception {
    testStringBounds();

    expect("title".toUpperCase().equals("TITLE"));
    expect("TITLE".toLowerCase().equals("title"));

    expect(new String(new byte[] { 99, 111, 109, 46, 101, 99, 111, 118, 97,
                                   116, 101, 46, 110, 97, 116, 46, 98, 117,
                                   115, 46, 83, 121, 109, 98, 111, 108 })
      .equals("com.ecovate.nat.bus.Symbol"));
    
    StringBuilder sb = new StringBuilder();
    sb.append('$');
    sb.append('2');
    expect(sb.substring(1).equals("2"));

    expect(Character.forDigit(Character.digit('0', 10), 10) == '0');
    expect(Character.forDigit(Character.digit('9', 10), 10) == '9');
    expect(Character.forDigit(Character.digit('b', 16), 16) == 'b');
    expect(Character.forDigit(Character.digit('f', 16), 16) == 'f');
    expect(Character.forDigit(Character.digit('z', 36), 36) == 'z');

    testDecode(false);
    testDecode(true);

    { java.io.ByteArrayOutputStream bout = new java.io.ByteArrayOutputStream();
      java.io.PrintStream pout = new java.io.PrintStream(bout, true, "UTF-8");
      String s = "I ♥ grape nuts";
      System.out.println(s);
      pout.println(s);

      expect
        (arraysEqual
         (bout.toByteArray(),
          (s + System.getProperty("line.separator")).getBytes("UTF-8")));

      expect
        (arraysEqual
         (bout.toByteArray(), append
          (new byte[] { 73, 32, -30, -103, -91, 32, 103, 114, 97, 112, 101,
                        32, 110, 117, 116, 115 },
            System.getProperty("line.separator").getBytes("UTF-8"))));
    }

    { byte[] bytes = new byte[] { (byte) 0xe9 };
      expect(new String(bytes, "ISO-8859-1").equals("\u00e9"));
      expect(arraysEqual("\u00e9".getBytes("ISO-8859-1"), bytes));

      java.io.ByteArrayOutputStream bout = new java.io.ByteArrayOutputStream();
      java.io.PrintStream pout
        = new java.io.PrintStream(bout, true, "ISO-8859-1");
      pout.print("\u00e9");
      expect(arraysEqual(bout.toByteArray(), bytes));
    }

    { String s = "\ud83d\ude00";
      byte[] utf8 = new byte[] { (byte) 0xf0, (byte) 0x9f,
                                 (byte) 0x98, (byte) 0x80 };
      expect(arraysEqual(s.getBytes("UTF-8"), utf8));
      expect(new String(utf8, "UTF-8").equals(s));

      java.io.ByteArrayOutputStream bout = new java.io.ByteArrayOutputStream();
      java.io.OutputStreamWriter writer
        = new java.io.OutputStreamWriter(bout, "UTF-8");
      writer.write(s);
      writer.flush();
      expect(arraysEqual(bout.toByteArray(), utf8));

      java.io.Reader reader = new java.io.InputStreamReader(
          new java.io.ByteArrayInputStream(utf8), "UTF-8");
      char[] decoded = new char[2];
      expect(reader.read(decoded, 0, decoded.length) == 2);
      expect(new String(decoded).equals(s));
    }

    { byte[] bytes = new byte[] { (byte) 0xe9 };
      java.io.Reader reader = new java.io.InputStreamReader(
          new java.io.ByteArrayInputStream(bytes), "latin-1");
      char[] decoded = new char[1];
      expect(reader.read(decoded, 0, decoded.length) == 1);
      expect(decoded[0] == '\u00e9');

      java.io.ByteArrayOutputStream bout = new java.io.ByteArrayOutputStream();
      java.io.OutputStreamWriter writer
        = new java.io.OutputStreamWriter(bout, "latin-1");
      writer.write("\u00e9");
      writer.flush();
      expect(arraysEqual(bout.toByteArray(), bytes));
    }

    expectUnsupportedEncoding(new Action() {
      public void run() throws Exception {
        new java.io.PrintStream(new java.io.ByteArrayOutputStream(),
                                true,
                                "UTF-16");
      }
    });

    expectUnsupportedEncoding(new Action() {
      public void run() throws Exception {
        new java.io.InputStreamReader(new java.io.ByteArrayInputStream(
                                      new byte[0]), "UTF-16");
      }
    });

    expectUnsupportedEncoding(new Action() {
      public void run() throws Exception {
        new java.io.OutputStreamWriter(new java.io.ByteArrayOutputStream(),
                                       "UTF-16");
      }
    });

    expect("abc".lastIndexOf('b', 100) == 1);

  }
}
