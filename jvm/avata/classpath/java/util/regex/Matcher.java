/* Copyright (c) 2008-2015, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for this software.  See license.txt for
   details. */

package java.util.regex;

/**
 * This is a work in progress.
 * 
 * @author zsombor and others
 */
public abstract class Matcher {
  protected CharSequence input;
  protected int start;
  protected int end;

  public Matcher(CharSequence input) {
    reset(input);
  }

  public abstract boolean matches();

  public boolean find() {
    int offset = end < 0 ? 0 : end + (start == end ? 1 : 0);
    if (offset > input.length()) {
      clearMatch();
      return false;
    }
    return find(offset);
  }

  public abstract boolean find(int start);

  public Matcher reset() {
    return reset(input);
  }

  public Matcher reset(CharSequence input) {
    this.input = input;
    clearMatch();
    return this;
  }

  public String replaceAll(String replacement) {
    return replace(replacement, Integer.MAX_VALUE);
  }

  public String replaceFirst(String replacement) {
    return replace(replacement, 1);
  }

  protected String replace(String replacement, int limit) {
    reset();

    StringBuilder sb = null;
    int index = 0;
    int count = 0;
    while (count < limit && index < input.length()) {
      if (find(index)) {
        if (sb == null) {
          sb = new StringBuilder();
        }
        if (start > index) {
          sb.append(input.subSequence(index, start));
        }
        sb.append(replacement);
        index = end;
        ++ count;
      } else if (index == 0) {
        return input.toString();
      } else {
        break;
      }
    }
    if (index < input.length()) {
      sb.append(input.subSequence(index, input.length()));
    }
    return sb.toString();
  }

  public int start() {
    checkMatchAvailable();
    return start;
  }

  public int end() {
    checkMatchAvailable();
    return end;
  }

  public String group() {
    return group(0);
  }

  public int start(int group) {
    checkGroup(group);
    return start;
  }

  public int end(int group) {
    checkGroup(group);
    return end;
  }

  public String group(int group) {
    checkGroup(group);
    return input.subSequence(start, end).toString();
  }

  public int groupCount() {
    return 0;
  }

  protected void clearMatch() {
    start = end = -1;
  }

  protected void checkFindStart(int offset) {
    if (offset < 0 || offset > input.length()) {
      throw new IndexOutOfBoundsException("Illegal start index");
    }
  }

  protected void checkMatchAvailable() {
    if (start < 0) {
      throw new IllegalStateException("No match available");
    }
  }

  protected void checkGroup(int group) {
    checkMatchAvailable();
    if (group < 0 || group > groupCount()) {
      throw new IndexOutOfBoundsException("No group " + group);
    }
  }
}
