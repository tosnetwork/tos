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
class TrivialMatcher extends Matcher {
  private final String pattern;

  TrivialMatcher(String pattern, CharSequence input) {
    super(input);
    this.pattern = pattern;
  }

  public boolean matches() {
    clearMatch();
    if (pattern.equals(input.toString())) {
      start = 0;
      end = input.length();
      return true;
    } else {
      return false;
    }
  }

  public boolean find(int offset) {
    checkFindStart(offset);
    clearMatch();
    String p = pattern;
    int i = TrivialPattern.indexOf(input, p, offset);
    if (i >= 0) {
      this.start = i;
      this.end = i + p.length();
      return true;
    } else {
      return false;
    }
  }
}
