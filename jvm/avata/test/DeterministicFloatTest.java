// Deterministic float/double opcode conformance tests.
// Validates NaN canonicalization, signed-zero, Infinity, overflow,
// subnormals, conversion clamping, and fcmpg/fcmpl NaN semantics.
// Values are stored in method-local arrays to prevent constant folding.
public class DeterministicFloatTest {

  static final int   FLOAT_CANONICAL_NAN_BITS  = 0x7FC00000;
  static final long  DOUBLE_CANONICAL_NAN_BITS = 0x7FF8000000000000L;

  static void check(String label, boolean cond) {
    if (!cond) throw new RuntimeException(label + " FAILED");
  }
  static void checkFBits(String label, float v, int expected) {
    int got = Float.floatToRawIntBits(v);
    if (got != expected)
      throw new RuntimeException(label + ": expected "
          + Integer.toHexString(expected) + " got " + Integer.toHexString(got));
  }
  static void checkDBits(String label, double v, long expected) {
    long got = Double.doubleToRawLongBits(v);
    if (got != expected)
      throw new RuntimeException(label + ": mismatch");
  }

  // Return NaN from a method so the compiler cannot fold it in callers.
  static float fnan()   { return Float.NaN; }
  static double dnan()  { return Double.NaN; }
  static float fpinf()  { return Float.POSITIVE_INFINITY; }
  static float fninf()  { return Float.NEGATIVE_INFINITY; }
  static double dpinf() { return Double.POSITIVE_INFINITY; }
  static double dninf() { return Double.NEGATIVE_INFINITY; }
  static float fnzero() { float[] a = {-0.0f}; return a[0]; }
  static double dnzero() { double[] a = {-0.0}; return a[0]; }

  static void testNaNCanon() {
    float nan = fnan();
    checkFBits("fadd NaN+1",  nan + 1.0f,          FLOAT_CANONICAL_NAN_BITS);
    checkFBits("fsub NaN-1",  nan - 1.0f,          FLOAT_CANONICAL_NAN_BITS);
    checkFBits("fmul NaN*1",  nan * 1.0f,          FLOAT_CANONICAL_NAN_BITS);
    checkFBits("fdiv NaN/1",  nan / 1.0f,          FLOAT_CANONICAL_NAN_BITS);
    checkFBits("frem NaN%1",  nan % 1.0f,          FLOAT_CANONICAL_NAN_BITS);
    checkFBits("fneg NaN",    -nan,                 FLOAT_CANONICAL_NAN_BITS);
    checkFBits("fadd 1+NaN",  1.0f + nan,          FLOAT_CANONICAL_NAN_BITS);

    double dnan = dnan();
    checkDBits("dadd NaN+1",  dnan + 1.0,          DOUBLE_CANONICAL_NAN_BITS);
    checkDBits("dsub NaN-1",  dnan - 1.0,          DOUBLE_CANONICAL_NAN_BITS);
    checkDBits("dmul NaN*1",  dnan * 1.0,          DOUBLE_CANONICAL_NAN_BITS);
    checkDBits("ddiv NaN/1",  dnan / 1.0,          DOUBLE_CANONICAL_NAN_BITS);
    checkDBits("drem NaN%1",  dnan % 1.0,          DOUBLE_CANONICAL_NAN_BITS);
    checkDBits("dneg NaN",    -dnan,                DOUBLE_CANONICAL_NAN_BITS);
  }

  static void testSignedZero() {
    float nz = fnzero();
    checkFBits("+0f+-0f", 0.0f + nz,  0x00000000); // +0
    checkFBits("-0f*1f",  nz * 1.0f,  0x80000000); // -0
    checkFBits("-0f/1f",  nz / 1.0f,  0x80000000); // -0

    double dnz = dnzero();
    checkDBits("+0d+-0d", 0.0 + dnz,  0x0000000000000000L);
    checkDBits("-0d*1d",  dnz * 1.0,  0x8000000000000000L);
    checkDBits("-0d/1d",  dnz / 1.0,  0x8000000000000000L);
  }

  static void testInfinity() {
    float inf = fpinf();
    check("Inf>0",          inf > 0.0f);
    check("isInf",          Float.isInfinite(inf));
    check("-Inf<0",         fninf() < 0.0f);
    check("Inf+Inf=Inf",    Float.isInfinite(inf + inf));
    checkFBits("Inf-Inf",   inf - inf, FLOAT_CANONICAL_NAN_BITS);

    double dinf = dpinf();
    check("dInf>0",         dinf > 0.0);
    checkDBits("dInf-dInf", dinf - dinf, DOUBLE_CANONICAL_NAN_BITS);
  }

  static void testOverflow() {
    check("fMAX*2=Inf",   Float.isInfinite(Float.MAX_VALUE * 2.0f));
    check("dMAX*2=Inf",   Double.isInfinite(Double.MAX_VALUE * 2.0));
  }

  static void testSubnormals() {
    float sm = Float.MIN_VALUE;
    check("fMIN>0",   sm > 0.0f);
    check("fMIN+fMIN not NaN", !Float.isNaN(sm + sm));

    double dm = Double.MIN_VALUE;
    check("dMIN>0",   dm > 0.0);
    check("dMIN+dMIN not NaN", !Double.isNaN(dm + dm));
  }

  static void testF2I() {
    check("f2i NaN=0",    (int) fnan()  == 0);
    check("f2i +Inf=MAX", (int) fpinf() == Integer.MAX_VALUE);
    check("f2i -Inf=MIN", (int) fninf() == Integer.MIN_VALUE);
    check("f2i 1=1",      (int) 1.0f    == 1);
    check("f2i -1=-1",    (int) -1.0f   == -1);
  }

  static void testF2L() {
    check("f2l NaN=0",    (long) fnan()  == 0L);
    check("f2l +Inf=MAX", (long) fpinf() == Long.MAX_VALUE);
    check("f2l -Inf=MIN", (long) fninf() == Long.MIN_VALUE);
    check("f2l 1=1",      (long) 1.0f    == 1L);
  }

  static void testD2I() {
    check("d2i NaN=0",    (int) dnan()  == 0);
    check("d2i +Inf=MAX", (int) dpinf() == Integer.MAX_VALUE);
    check("d2i -Inf=MIN", (int) dninf() == Integer.MIN_VALUE);
    check("d2i 1=1",      (int) 1.0     == 1);
  }

  static void testD2L() {
    check("d2l NaN=0",    (long) dnan()  == 0L);
    check("d2l +Inf=MAX", (long) dpinf() == Long.MAX_VALUE);
    check("d2l -Inf=MIN", (long) dninf() == Long.MIN_VALUE);
    check("d2l 1=1",      (long) 1.0     == 1L);
  }

  static void testCmpNaN() {
    float nan = fnan();
    check("NaN!=NaN",  !(nan == nan));
    check("NaN<1=F",   !(nan < 1.0f));
    check("NaN>1=F",   !(nan > 1.0f));
    // ternary: exercises fcmpg/fcmpl
    int fi = (nan < 1.0f) ? -1 : ((nan > 1.0f) ? 1 : 0);
    check("fcmp NaN ternary=0", fi == 0);

    double dnan = dnan();
    check("dNaN!=dNaN", !(dnan == dnan));
    int di = (dnan < 1.0) ? -1 : ((dnan > 1.0) ? 1 : 0);
    check("dcmp NaN ternary=0", di == 0);
  }

  static void testD2FNaN() {
    checkFBits("d2f NaN", (float) dnan(), FLOAT_CANONICAL_NAN_BITS);
  }

  static void testF2DNaN() {
    checkDBits("f2d NaN", (double) fnan(), DOUBLE_CANONICAL_NAN_BITS);
  }

  static void testConversions() {
    check("i2f 42",  (float) 42  == 42.0f);
    check("i2d 42",  (double) 42 == 42.0);
    check("l2f 10",  (float) 10L  == 10.0f);
    check("l2d 10",  (double) 10L == 10.0);
    checkFBits("d2f 1.0", (float) 1.0, 0x3F800000);
    checkDBits("f2d 1.0", (double) 1.0f, 0x3FF0000000000000L);
  }

  static void testRepeatability() {
    float a = 1.0f, b = 2.0f;
    check("fadd repeatable", (a + b) == (a + b));
    check("fadd correct",    (a + b) == 3.0f);
    double da = 1.0, db = 2.0;
    check("dadd repeatable", (da + db) == (da + db));
    check("dadd correct",    (da + db) == 3.0);
  }

  public static void main(String[] args) {
    testNaNCanon();
    testSignedZero();
    testInfinity();
    testOverflow();
    testSubnormals();
    testF2I();
    testF2L();
    testD2I();
    testD2L();
    testCmpNaN();
    testD2FNaN();
    testF2DNaN();
    testConversions();
    testRepeatability();
    System.out.println("DeterministicFloatTest: all passed");
  }
}
