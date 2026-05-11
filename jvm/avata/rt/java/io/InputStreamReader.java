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

public class InputStreamReader extends Reader {
  private static final int MultibytePadding = 4;
  private static final String UTF_8_ENCODING = "UTF-8";
  private static final String ISO_8859_1_ENCODING = "ISO-8859-1";
  private static final String LATIN_1_ENCODING = "LATIN-1";

  private final InputStream in;
  private final String encoding;

  public InputStreamReader(InputStream in) {
    this.in = in;
    this.encoding = UTF_8_ENCODING;
  }

  public InputStreamReader(InputStream in, String encoding)
    throws UnsupportedEncodingException
  {
    this.in = in;
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
  
  public int read(char[] b, int offset, int length) throws IOException {
    if (length == 0) {
      return 0;
    }
    if (encoding.equals(ISO_8859_1_ENCODING)) {
      byte[] buffer = new byte[length];
      int c = in.read(buffer, 0, length);
      if (c <= 0) {
        return c;
      }
      char[] decoded = Iso88591.decode(buffer, 0, c);
      System.arraycopy(decoded, 0, b, offset, c);
      return c;
    }

    byte[] buffer = new byte[length + MultibytePadding];
    int bufferLength = length;
    int bufferOffset = 0;
    while (true) {
      int c = in.read(buffer, bufferOffset, bufferLength);

      if (c <= 0) {
        if (bufferOffset > 0) {
          // if we've reached the end of the stream while trying to
          // read a multibyte character, we still need to return any
          // competely-decoded characters, plus \ufffd to indicate an
          // unknown character
          c = 1;
          while (bufferOffset > 0) {
            char[] buffer16 = Utf8.decode16(buffer, 0, bufferOffset);

            if (buffer16 != null) {
              System.arraycopy(buffer16, 0, b, offset, buffer16.length);
              
              c = buffer16.length + 1;
              break;
            } else {
              -- bufferOffset;
            }
          }

          b[offset + c - 1] = '\ufffd';
        }

        return c;
      }

      bufferOffset += c;

      char[] buffer16 = Utf8.decode16(buffer, 0, bufferOffset);

      if (buffer16 != null) {
        bufferOffset = 0;

        System.arraycopy(buffer16, 0, b, offset, buffer16.length);

        return buffer16.length;
      } else {
        // the buffer ended in an incomplete multibyte character, so
        // we try to read a another byte at a time until it's complete
        bufferLength = 1;
      }
    }
  }

  public void close() throws IOException {
    in.close();
  }
}
