/* Copyright (c) 2008-2015, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for this software.  See license.txt for
   details. */

package java.io;

import java.internal.Iso88591;
import java.internal.Utf8;

public class OutputStreamWriter extends Writer {
  private static final String UTF_8_ENCODING = "UTF-8";
  private static final String ISO_8859_1_ENCODING = "ISO-8859-1";
  private static final String LATIN_1_ENCODING = "LATIN-1";

  private final OutputStream out;
  private final String encoding;

  public OutputStreamWriter(OutputStream out) {
    this.out = out;
    this.encoding = UTF_8_ENCODING;
  }

  public OutputStreamWriter(OutputStream out, String encoding)
    throws UnsupportedEncodingException
  {
    this.out = out;
    if (encoding == null) {
      throw new NullPointerException();
    }
    if (encoding.equalsIgnoreCase(UTF_8_ENCODING)) {
      this.encoding = UTF_8_ENCODING;
    } else if (encoding.equalsIgnoreCase(ISO_8859_1_ENCODING)
               || encoding.equalsIgnoreCase(LATIN_1_ENCODING)) {
      this.encoding = ISO_8859_1_ENCODING;
    } else {
      throw new UnsupportedEncodingException(encoding);
    }
  }
  
  public void write(char[] b, int offset, int length) throws IOException {
    out.write(encoding.equals(UTF_8_ENCODING)
              ? Utf8.encode(b, offset, length)
              : Iso88591.encode(b, offset, length));
  }

  public void flush() throws IOException {
    out.flush();
  }

  public void close() throws IOException {
    out.close();
  }
}
