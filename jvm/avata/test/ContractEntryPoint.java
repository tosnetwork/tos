public class ContractEntryPoint {
  public static void ok() {
  }

  public static void fail() {
    throw new RuntimeException("contract failed");
  }

  public static void burn() {
    int sum = 0;
    for (int i = 0; i < 100; ++i) {
      sum += i;
    }
    if (sum == 0) {
      throw new RuntimeException();
    }
  }

  public static void main(String[] args) {
    ok();
    burn();
  }
}
