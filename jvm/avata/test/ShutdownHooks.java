public class ShutdownHooks {
  public static void main(String[] args) {
    Runtime.getRuntime().addShutdownHook(new Thread() {
      public void run() {
        System.out.print("h");
      }
    });
  }
}
