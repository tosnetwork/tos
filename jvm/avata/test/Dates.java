import java.text.FieldPosition;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

public class Dates {
  private final static long EPOCH = 1234567890;
  private final static String TEXT = "2009-02-13T23:31:30";

  private static void expect(boolean v) {
    if (! v) throw new RuntimeException();
  }

  public static void main(String[] args) throws Exception {
    SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");
    format.setTimeZone(TimeZone.getTimeZone("GMT"));
    Date date = format.parse("1970-01-01T00:00:00");
    expect(0 == date.getTime());

    date = new Date(EPOCH * 1000l);
    String actual = format.format(date, new StringBuffer(), new FieldPosition(0)).toString();
    expect(TEXT.equals(actual));

    date = format.parse(TEXT);
    expect(EPOCH == date.getTime() / 1000l);

    SimpleDateFormat dateOnly = new SimpleDateFormat("yyyy-MM-dd");
    dateOnly.setTimeZone(TimeZone.getTimeZone("GMT"));
    expect("2009-02-13".equals(dateOnly.format(new Date(EPOCH * 1000l))));
    expect(0 == dateOnly.parse("1970-01-01").getTime());

    SimpleDateFormat compact = new SimpleDateFormat("yyyyMMddHHmmss");
    compact.setTimeZone(TimeZone.getTimeZone("GMT"));
    expect("20090213233130".equals(compact.format(new Date(EPOCH * 1000l))));
    expect(EPOCH == compact.parse("20090213233130").getTime() / 1000l);

    SimpleDateFormat spaced = new SimpleDateFormat("yyyy-M-d HH:mm:ss");
    spaced.setTimeZone(TimeZone.getTimeZone("GMT"));
    expect("2009-2-13 23:31:30".equals(spaced.format(new Date(EPOCH * 1000l))));
    expect(EPOCH == spaced.parse("2009-2-13 23:31:30").getTime() / 1000l);

    SimpleDateFormat quoted = new SimpleDateFormat("yyyy-MM-dd 'at' HH:mm:ss");
    quoted.setTimeZone(TimeZone.getTimeZone("GMT"));
    expect("2009-02-13 at 23:31:30".equals(quoted.format(new Date(EPOCH * 1000l))));

    try {
      new SimpleDateFormat("yyyy-MMM-dd");
      expect(false);
    } catch (UnsupportedOperationException e) {
      // locale-specific month text is intentionally outside the deterministic subset
    }
  }
}
