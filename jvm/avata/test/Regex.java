import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Regex {
  private interface Thrower {
    void run();
  }

  private static void expect(boolean v) {
    if (! v) throw new RuntimeException();
  }

  private static void expectIllegalState(Thrower thrower) {
    try {
      thrower.run();
      expect(false);
    } catch (IllegalStateException e) {
      // expected
    }
  }

  private static void expectIndexOutOfBounds(Thrower thrower) {
    try {
      thrower.run();
      expect(false);
    } catch (IndexOutOfBoundsException e) {
      // expected
    }
  }

  private static Matcher getMatcher(String regex, String string) {
    return Pattern.compile(regex).matcher(string);
  }

  private static void expectMatch(String regex, String string) {
    expect(getMatcher(regex, string).matches());
  }

  private static void expectNoMatch(String regex, String string) {
    expect(!getMatcher(regex, string).matches());
  }

  private static void expectGroups(String regex, String string,
      String... groups) {
    Matcher matcher = getMatcher(regex, string);
    expect(matcher.matches());
    expect(matcher.groupCount() == groups.length);
    for (int i = 1; i <= groups.length; ++i) {
      if (groups[i - 1] == null) {
        expect(matcher.group(i) == null);
      } else {
        expect(groups[i - 1].equals(matcher.group(i)));
      }
    }
  }

  private static void expectFind(String regex, String string,
      String... matches)
  {
    Matcher matcher = getMatcher(regex, string);
    int i = 0;
    while (i < matches.length) {
      expect(matcher.find());
      expect(matches[i++].equals(matcher.group()));
    }
    expect(!matcher.find());
  }

  private static void expectSplit(String regex, String string,
      String... list)
  {
    String[] array = Pattern.compile(regex).split(string);
    expect(array.length == list.length);
    for (int i = 0; i < list.length; ++ i) {
      expect(list[i].equals(array[i]));
    }
  }

  private static void expectMatcherState() {
    final Matcher trivial = Pattern.compile("abc").matcher("abc");
    expect(trivial.groupCount() == 0);
    expectIllegalState(new Thrower() { public void run() { trivial.start(); } });
    expectIllegalState(new Thrower() { public void run() { trivial.end(); } });
    expectIllegalState(new Thrower() { public void run() { trivial.group(); } });
    expectIllegalState(new Thrower() { public void run() { trivial.start(1); } });
    expect(trivial.matches());
    expect(trivial.start() == 0);
    expect(trivial.end() == 3);
    expect("abc".equals(trivial.group()));
    expect("abc".equals(trivial.group(0)));
    expectIndexOutOfBounds(new Thrower() { public void run() { trivial.start(1); } });
    expectIndexOutOfBounds(new Thrower() { public void run() { trivial.end(-1); } });
    expectIndexOutOfBounds(new Thrower() { public void run() { trivial.group(1); } });
    expect(!trivial.find());
    expectIllegalState(new Thrower() { public void run() { trivial.start(); } });

    final Matcher grouped = Pattern.compile("(a)(b)?").matcher("a");
    expect(grouped.groupCount() == 2);
    expectIllegalState(new Thrower() { public void run() { grouped.group(0); } });
    expect(grouped.matches());
    expect(grouped.start(0) == 0);
    expect(grouped.end(0) == 1);
    expect("a".equals(grouped.group(0)));
    expect(grouped.start(1) == 0);
    expect(grouped.end(1) == 1);
    expect("a".equals(grouped.group(1)));
    expect(grouped.start(2) == -1);
    expect(grouped.end(2) == -1);
    expect(grouped.group(2) == null);
    expectIndexOutOfBounds(new Thrower() { public void run() { grouped.start(3); } });
    expectIndexOutOfBounds(new Thrower() { public void run() { grouped.end(-1); } });
    expectIndexOutOfBounds(new Thrower() { public void run() { grouped.group(3); } });

    final Matcher trivialFind = Pattern.compile("a").matcher("a");
    expectIndexOutOfBounds(new Thrower() { public void run() { trivialFind.find(-1); } });
    expectIndexOutOfBounds(new Thrower() { public void run() { trivialFind.find(2); } });
    expect(trivialFind.find());
    expect(trivialFind.start() == 0);
    expect(!trivialFind.find());
    expectIllegalState(new Thrower() { public void run() { trivialFind.group(); } });

    final Matcher regexFind = Pattern.compile("(a)").matcher("a");
    expectIndexOutOfBounds(new Thrower() { public void run() { regexFind.find(-1); } });
    expectIndexOutOfBounds(new Thrower() { public void run() { regexFind.find(2); } });
    expect(regexFind.find());
    expect(regexFind.start() == 0);
    expect("a".equals(regexFind.group(1)));
    expect(!regexFind.find());
    expectIllegalState(new Thrower() { public void run() { regexFind.end(); } });
  }

  public static void main(String[] args) {
    expectMatcherState();
    expectMatch("a(bb)?a", "abba");
    expectNoMatch("a(bb)?a", "abbba");
    expectNoMatch("a(bb)?a", "abbaa");
    expectGroups("a(a*?)(a?)(a??)(a+)(a*)a", "aaaaaa", "", "a", "", "aaa", "");
    expectMatch("...", "abc");
    expectNoMatch(".", "\n");
    expectGroups("a(bb)*a", "abbbba", "bb");
    expectGroups("a(bb)?(bb)+a", "abba", null, "bb");
    expectFind(" +", "Hello  ,   world! ", "  ", "   ", " ");
    expectMatch("[0-9A-Fa-f]+", "08ef");
    expectNoMatch("[0-9A-Fa-f]+", "08@ef");
    expectGroups("(?:a)", "a");
    expectGroups("a|(b|c)", "a", (String)null);
    expectGroups("a|(b|c)", "c", "c");
    expectGroups("(?=a)a", "a");
    expectGroups(".*(o)(?<=[A-Z][a-z]{1,4})", "Hello", "o");
    expectNoMatch("(?!a).", "a");
    expectMatch("[\\d]", "0");
    expectMatch("\\0777", "?7");
    expectMatch("\\a", "\007");
    expectMatch("\\\\", "\\");
    expectMatch("\\x4A", "J");
    expectMatch("\\x61", "a");
    expectMatch("\\078", "\0078");
    expectSplit("(?<=\\w)(?=\\W)|(?<=\\W)(?=\\w)", "a + b * x",
      "a", " + ", "b", " * ", "x");
    expectMatch("[0-9[def]]", "f");
    expectNoMatch("[a-z&&[^d-f]]", "f");
    expectSplit("^H", "Hello\nHobbes!", "", "ello\nHobbes!");
    expectSplit("o.*?$", "Hello\r\nHobbes!", "Hello\r\nH");
    try {
      expectSplit("\\b", "a+ b + c\nd", "", "a", "+ ", "b", " + ", "c", "\n", "d");
    } catch (RuntimeException e) {
      // Java 8 changed the semantics of split, so if we're on 8, the
      // above will fail and this will succeed:
      expectSplit("\\b", "a+ b + c\nd", "a", "+ ", "b", " + ", "c", "\n", "d");
    }
    expectSplit("\\B", "Hi Cal!", "H", "i C", "a", "l!");
    expectMatch("a{2,5}", "aaaa");
    expectGroups("a??(a{2,5}?)", "aaaa", "aaaa");
    expectGroups("a??(a{3}?)", "aaaa", "aaa");
    expectNoMatch("a(a{3}?)", "aaaaa");
    expectMatch("a(a{3,}?)", "aaaaa");

    expect(Pattern.compile("abc", Pattern.CASE_INSENSITIVE)
           .matcher("AbC").matches());
    expect(Pattern.compile("[a-f]+", Pattern.CASE_INSENSITIVE)
           .matcher("AF").matches());
    expect(Pattern.compile("a.b", Pattern.LITERAL)
           .matcher("a.b").matches());
    expect(!Pattern.compile("a.b", Pattern.LITERAL)
           .matcher("axb").matches());
    expect(Pattern.compile("a.b", Pattern.LITERAL | Pattern.CASE_INSENSITIVE)
           .matcher("A.B").matches());
    expect(Pattern.compile(".", Pattern.DOTALL).matcher("\n").matches());
    expect(!Pattern.compile(".").matcher("\n").matches());
    Matcher matcher = Pattern.compile("^H", Pattern.MULTILINE)
      .matcher("ello\nHobbes");
    expect(matcher.find());
    expect(matcher.start() == 5);
    expect(!Pattern.compile("^H").matcher("ello\nHobbes").find());
    expect(Pattern.compile("x", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE)
           .flags() == (Pattern.CASE_INSENSITIVE | Pattern.MULTILINE));
    try {
      Pattern.compile("x", 0x400);
      expect(false);
    } catch (IllegalArgumentException e) {
      // expected
    }
    try {
      Pattern.compile("x", Pattern.UNICODE_CHARACTER_CLASS);
      expect(false);
    } catch (UnsupportedOperationException e) {
      // expected
    }
  }
}
