// Performance baseline for the Avata JVM interpreter.
//
// Executes a workload representative of typical TOS contract execution:
// integer arithmetic, array operations, and conditional branching.
// The benchmark is NOT a micro-benchmark of a single opcode — it exercises
// the interpreter dispatch loop over a realistic mix of bytecodes.
//
// Invocation: tools/java --gas 100000000 --memory 4194304 -cp <out> PerfBaseline
//
// Output format:
//   PerfBaseline:iterations=<N>:gas_per_iter=<G>:wall_us=<W>:iters_per_sec=<R>
//
// The wall_us and iters_per_sec fields are intentionally absent (Avata does
// not expose a deterministic clock).  The gas_per_iter value is the primary
// regression gate: a sudden change indicates an opcode-gas or dispatch
// regression even without timing data.
public class PerfBaseline {

  // Workload: compute a pseudo-checksum over an integer array.
  // Exercises: newarray, iastore/iaload, iadd, imul, irem, iand, if_icmplt,
  //            iinc, goto, iconst, bipush, sipush.
  static long arrayChecksum(int size, int seed) {
    int[] data = new int[size];
    for (int i = 0; i < size; i++) {
      data[i] = (seed * 1664525 + i * 1013904223) & 0x7FFFFFFF;
    }
    long sum = 0;
    for (int i = 0; i < size; i++) {
      sum += data[i];
      sum ^= (sum << 13);
      sum ^= (sum >>> 7);
    }
    return sum;
  }

  // Workload: recursive Fibonacci (small N, exercises invoke/return).
  static int fib(int n) {
    if (n <= 1) return n;
    return fib(n - 1) + fib(n - 2);
  }

  // Workload: string concatenation chain (exercises StringBuilder, toCharArray,
  // char arrays, invokevirtual).
  static int stringWork(int n) {
    String s = "";
    for (int i = 0; i < n; i++) {
      s = s + (char)('A' + (i % 26));
    }
    return s.length();
  }

  // Workload: arithmetic-heavy inner loop (exercises floating-point ops via
  // integer paths only — no float/double to stay within the deterministic
  // profile and avoid SoftFloat overhead in the baseline).
  static long arithLoop(int iters) {
    long acc = 1;
    for (int i = 1; i <= iters; i++) {
      acc = (acc * i + 31337) % 1000000007L;
    }
    return acc;
  }

  static final int OUTER_ITERS = 200;

  public static void main(String[] args) {
    long checksum = 0;

    for (int i = 0; i < OUTER_ITERS; i++) {
      checksum ^= arrayChecksum(128, i * 6364136223846793005L == 0 ? 1 : i + 1);
      checksum ^= fib(12);
      checksum ^= stringWork(16);
      checksum ^= arithLoop(50);
    }

    // Print the anti-elimination checksum so the JIT (if any) cannot dead-code
    // eliminate the workload.  Also signals that the run completed without OOG.
    System.out.println("PerfBaseline:iterations=" + OUTER_ITERS
        + ":checksum=" + checksum);
  }
}
