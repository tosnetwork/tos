/* Copyright (c) 2008-2015, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for this software.  See license.txt for
   details. */

package java.text;

import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;

public class SimpleDateFormat {
  private String pattern;

  public SimpleDateFormat(String pattern) {
    if (pattern == null) {
      throw new NullPointerException();
    }
    validatePattern(pattern);
    this.pattern = pattern;
  }

  public void setTimeZone(TimeZone tz) {
    if(!tz.getDisplayName().equals("GMT")) {
      throw new UnsupportedOperationException();
    }
  }

  public StringBuffer format(Date date, StringBuffer buffer, FieldPosition position) {
    Calendar calendar = Calendar.getInstance();
    calendar.setTime(date);
    for (int i = 0; i < pattern.length();) {
      char ch = pattern.charAt(i);
      if (ch == '\'') {
        i = appendQuoted(pattern, i, buffer);
      } else if (isPatternLetter(ch)) {
        int count = countRepeated(pattern, i);
        appendField(buffer, calendar, ch, count);
        i += count;
      } else {
        buffer.append(ch);
        i++;
      }
    }
    return buffer;
  }

  public String format(Date date) {
    return format(date, new StringBuffer(), new FieldPosition(0)).toString();
  }

  public Date parse(String text) {
    return parse(text, new ParsePosition(0));
  }

  public Date parse(String text, ParsePosition position) {
    int index = position.getIndex();
    try {
      Calendar calendar = Calendar.getInstance();
      setDefaults(calendar);
      for (int i = 0; i < pattern.length();) {
        char ch = pattern.charAt(i);
        if (ch == '\'') {
          int next = parseQuoted(pattern, i, text, index);
          index += quotedLength(pattern, i);
          i = next;
        } else if (isPatternLetter(ch)) {
          int count = countRepeated(pattern, i);
          index = parseField(text, index, count, calendar, ch);
          i += count;
        } else {
          index = expectPrefix(text, index, String.valueOf(ch));
          i++;
        }
      }
      position.setIndex(index);
      return calendar.getTime();
    } catch (ParseException e) {
      position.setErrorIndex(index);
      return null;
    }
  }

  private static void validatePattern(String pattern) {
    for (int i = 0; i < pattern.length();) {
      char ch = pattern.charAt(i);
      if (ch == '\'') {
        i = validateQuoted(pattern, i);
      } else if (isPatternLetter(ch)) {
        int count = countRepeated(pattern, i);
        validateField(ch, count, pattern);
        i += count;
      } else {
        i++;
      }
    }
  }

  private static boolean isPatternLetter(char ch) {
    return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z');
  }

  private static int countRepeated(String pattern, int offset) {
    char ch = pattern.charAt(offset);
    int count = 1;
    while (offset + count < pattern.length()
           && pattern.charAt(offset + count) == ch) {
      count++;
    }
    return count;
  }

  private static void validateField(char ch, int count, String pattern) {
    switch (ch) {
    case 'y':
      if (count == 4) {
        return;
      }
      break;
    case 'M':
      if (count <= 2) {
        return;
      }
      break;
    case 'd':
    case 'H':
    case 'm':
    case 's':
      if (count <= 2) {
        return;
      }
      break;
    }
    throw new UnsupportedOperationException("Unsupported pattern: " + pattern);
  }

  private static int validateQuoted(String pattern, int offset) {
    if (offset + 1 < pattern.length() && pattern.charAt(offset + 1) == '\'') {
      return offset + 2;
    }

    for (int i = offset + 1; i < pattern.length(); ++i) {
      if (pattern.charAt(i) == '\'') {
        if (i + 1 < pattern.length() && pattern.charAt(i + 1) == '\'') {
          i++;
        } else {
          return i + 1;
        }
      }
    }
    throw new IllegalArgumentException("Unterminated quote in pattern");
  }

  private static int appendQuoted(String pattern, int offset, StringBuffer buffer) {
    if (offset + 1 < pattern.length() && pattern.charAt(offset + 1) == '\'') {
      buffer.append('\'');
      return offset + 2;
    }

    for (int i = offset + 1; i < pattern.length(); ++i) {
      char ch = pattern.charAt(i);
      if (ch == '\'') {
        if (i + 1 < pattern.length() && pattern.charAt(i + 1) == '\'') {
          buffer.append('\'');
          i++;
        } else {
          return i + 1;
        }
      } else {
        buffer.append(ch);
      }
    }
    throw new IllegalArgumentException("Unterminated quote in pattern");
  }

  private static int parseQuoted(String pattern, int offset, String text, int textOffset)
    throws ParseException
  {
    if (offset + 1 < pattern.length() && pattern.charAt(offset + 1) == '\'') {
      expectPrefix(text, textOffset, "'");
      return offset + 2;
    }

    StringBuffer literal = new StringBuffer();
    int next = appendQuoted(pattern, offset, literal);
    expectPrefix(text, textOffset, literal.toString());
    return next;
  }

  private static int quotedLength(String pattern, int offset) {
    if (offset + 1 < pattern.length() && pattern.charAt(offset + 1) == '\'') {
      return 1;
    }

    StringBuffer literal = new StringBuffer();
    appendQuoted(pattern, offset, literal);
    return literal.length();
  }

  private static void appendField(
    StringBuffer buffer, Calendar calendar, char field, int count)
  {
    int value;
    switch (field) {
    case 'y':
      value = calendar.get(Calendar.YEAR);
      break;
    case 'M':
      value = calendar.get(Calendar.MONTH) + 1;
      break;
    case 'd':
      value = calendar.get(Calendar.DAY_OF_MONTH);
      break;
    case 'H':
      value = calendar.get(Calendar.HOUR_OF_DAY);
      break;
    case 'm':
      value = calendar.get(Calendar.MINUTE);
      break;
    case 's':
      value = calendar.get(Calendar.SECOND);
      break;
    default:
      throw new IllegalArgumentException();
    }
    pad(buffer, value, count);
  }

  private static void setDefaults(Calendar calendar) {
    calendar.set(Calendar.YEAR, 1970);
    calendar.set(Calendar.MONTH, 0);
    calendar.set(Calendar.DAY_OF_MONTH, 1);
    calendar.set(Calendar.HOUR_OF_DAY, 0);
    calendar.set(Calendar.MINUTE, 0);
    calendar.set(Calendar.SECOND, 0);
  }

  private static void pad(StringBuffer buffer, int value, int digits) {
    int i = value == 0 ? 1 : value;
    while (i > 0) {
      i /= 10;
      --digits;
    }
    while (digits-- > 0) {
      buffer.append('0');
    }
    buffer.append(value);
  }

  private static int parseField(String text, int offset, int length, Calendar calendar, int field, int adjustment) throws ParseException {
    if (text.length() < offset + length) throw new ParseException("Short date: " + text, offset);
    try {
      int value = Integer.parseInt(text.substring(offset, offset + length), 10);
      calendar.set(field, value + adjustment);
    } catch (NumberFormatException e) {
      throw new ParseException("Not a number: " + text, offset);
    }
    return offset + length;
  }

  private static int parseField(String text, int offset, int length, Calendar calendar, char field) throws ParseException {
    if (length == 1 && field != 'y'
        && text.length() > offset + 1
        && text.charAt(offset + 1) >= '0'
        && text.charAt(offset + 1) <= '9') {
      length = 2;
    }

    if (text.length() < offset + length) throw new ParseException("Short date: " + text, offset);
    final int value;
    try {
      value = Integer.parseInt(text.substring(offset, offset + length), 10);
    } catch (NumberFormatException e) {
      throw new ParseException("Not a number: " + text, offset);
    }

    switch (field) {
    case 'y':
      calendar.set(Calendar.YEAR, value);
      break;
    case 'M':
      if (value < 1 || value > 12) throw new ParseException("Invalid month: " + text, offset);
      calendar.set(Calendar.MONTH, value - 1);
      break;
    case 'd':
      if (value < 1 || value > 31) throw new ParseException("Invalid day: " + text, offset);
      calendar.set(Calendar.DAY_OF_MONTH, value);
      break;
    case 'H':
      if (value < 0 || value > 23) throw new ParseException("Invalid hour: " + text, offset);
      calendar.set(Calendar.HOUR_OF_DAY, value);
      break;
    case 'm':
      if (value < 0 || value > 59) throw new ParseException("Invalid minute: " + text, offset);
      calendar.set(Calendar.MINUTE, value);
      break;
    case 's':
      if (value < 0 || value > 59) throw new ParseException("Invalid second: " + text, offset);
      calendar.set(Calendar.SECOND, value);
      break;
    default:
      throw new IllegalArgumentException();
    }
    return offset + length;
  }

  private static int expectPrefix(String text, int offset, String prefix) throws ParseException {
    if (text.length() <= offset) throw new ParseException("Short date: " + text, offset);
    if (! text.substring(offset).startsWith(prefix)) throw new ParseException("Parse error: " + text, offset);
    return offset + prefix.length();
  }
}
