public class Exceptions {
  private static void evenMoreDangerous() {
    throw new RuntimeException("chaos! panic! overwhelming anxiety!");
  }

  private static void moreDangerous() {
    evenMoreDangerous();
  }

  private static void dangerous() {
    moreDangerous();
  }

  private static void expect(boolean v) {
    if (! v) throw new RuntimeException();
  }

  public static void main(String[] args) {
    boolean threw = false;
    try {
      dangerous();
    } catch (Exception e) {
      e.printStackTrace();
      threw = true;
    }
    expect(threw);
  }

}
