/* Copyright (c) 2008-2015, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for this software.  See license.txt for
   details. */

package java.util;

public class Locale {
  private static final Locale DEFAULT;

  public static final Locale ENGLISH = new Locale("en", "");
  public static final Locale FRENCH = new Locale("fr", "");
  public static final Locale GERMAN = new Locale("de", "");
  public static final Locale ITALIAN = new Locale("it", "");
  public static final Locale JAPANESE = new Locale("ja", "");
  public static final Locale KOREAN = new Locale("ko", "");
  public static final Locale CHINESE = new Locale("zh", "");
  public static final Locale SIMPLIFIED_CHINESE = new Locale("zh", "CN");
  public static final Locale TRADITIONAL_CHINESE = new Locale("zh", "TW");

  public static final Locale FRANCE = new Locale("fr", "FR");
  public static final Locale GERMANY = new Locale("de", "DE");
  public static final Locale ITALY = new Locale("it", "IT");
  public static final Locale JAPAN = new Locale("ja", "JP");
  public static final Locale KOREA = new Locale("ko", "KR");
  public static final Locale CHINA = SIMPLIFIED_CHINESE;
  public static final Locale PRC = SIMPLIFIED_CHINESE;
  public static final Locale TAIWAN = TRADITIONAL_CHINESE;
  public static final Locale UK = new Locale("en", "GB");
  public static final Locale US = new Locale("en", "US");
  public static final Locale CANADA = new Locale("en", "CA");
  public static final Locale CANADA_FRENCH = new Locale("fr", "CA");
  public static final Locale ROOT = new Locale("", "");

  private final String language;
  private final String country;
  private final String variant;
  private int hashCode;

  static {
    DEFAULT = new Locale(System.getProperty("user.language"),
                         System.getProperty("user.region"));
  }

  public Locale(String language, String country, String variant) {
    if (language == null || country == null || variant == null) {
      throw new NullPointerException();
    }
    this.language = convertOldISOCodes(toLower(language));
    this.country = toUpper(country);
    this.variant = variant;
  }

  public Locale(String language, String country) {
    this(language, country, "");
  }

  public Locale(String language) {
    this(language, "");
  }

  public String getLanguage() {
    return language;
  }

  public String getCountry() {
    return country;
  }

  public String getVariant() {
    return variant;
  }

  public static Locale getDefault() {
    return DEFAULT;
  }

  public boolean equals(Object o) {
    if (this == o) {
      return true;
    } else if (o instanceof Locale) {
      Locale l = (Locale) o;
      return language.equals(l.language)
        && country.equals(l.country)
        && variant.equals(l.variant);
    } else {
      return false;
    }
  }

  public int hashCode() {
    if (hashCode == 0) {
      hashCode = language.hashCode() ^ country.hashCode() ^ variant.hashCode();
    }
    return hashCode;
  }

  public final String toString() {
    boolean hasLanguage = language.length() != 0;
    boolean hasCountry  = country.length()  != 0;
    boolean hasVariant  = variant.length()  != 0;

    if (!hasLanguage && !hasCountry) return "";
    return language + (hasCountry || hasVariant ? '_' + country : "") + (hasVariant ? '_' + variant : "");
  }

  private static String toLower(String s) {
    char[] result = null;

    for (int i = 0; i < s.length(); ++i) {
      char c = s.charAt(i);
      if (c >= 'A' && c <= 'Z') {
        if (result == null) {
          result = s.toCharArray();
        }
        result[i] = (char) ((c - 'A') + 'a');
      } else if (result != null) {
        result[i] = c;
      }
    }

    return result == null ? s : new String(result);
  }

  private static String toUpper(String s) {
    char[] result = null;

    for (int i = 0; i < s.length(); ++i) {
      char c = s.charAt(i);
      if (c >= 'a' && c <= 'z') {
        if (result == null) {
          result = s.toCharArray();
        }
        result[i] = (char) ((c - 'a') + 'A');
      } else if (result != null) {
        result[i] = c;
      }
    }

    return result == null ? s : new String(result);
  }

  private static String convertOldISOCodes(String language) {
    if (language.equals("he")) {
      return "iw";
    } else if (language.equals("yi")) {
      return "ji";
    } else if (language.equals("id")) {
      return "in";
    } else {
      return language;
    }
  }
}
