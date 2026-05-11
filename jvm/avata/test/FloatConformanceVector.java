// Cross-platform float/double opcode conformance vector.
//
// Prints one "label:hexvalue" line per operation.  Run on any target platform
// and diff against float-conformance-reference.txt to detect IEEE 754
// divergence caused by host-CPU or SoftFloat configuration differences.
//
// All operands are loaded through single-element arrays so javac cannot
// constant-fold the arithmetic at compile time.
public class FloatConformanceVector {

  static void outf(String label, float v) {
    System.out.println(label + ":" + Integer.toHexString(Float.floatToRawIntBits(v)));
  }
  static void outd(String label, double v) {
    System.out.println(label + ":" + Long.toHexString(Double.doubleToRawLongBits(v)));
  }
  static void outi(String label, int v)  { System.out.println(label + ":" + v); }
  static void outl(String label, long v) { System.out.println(label + ":" + v); }

  // Anti-fold wrappers: wrap in a single-element array, read back.
  static float  fv(float  v) { float[]  a = {v}; return a[0]; }
  static double dv(double v) { double[] a = {v}; return a[0]; }
  static int    iv(int    v) { int[]    a = {v}; return a[0]; }
  static long   lv(long   v) { long[]   a = {v}; return a[0]; }

  // Shorthand constants loaded through the anti-fold helper so they are
  // runtime values, not javac compile-time literals.
  static float  F1   () { return fv(1.0f); }
  static float  F2   () { return fv(2.0f); }
  static float  F1P5 () { return fv(1.5f); }
  static float  FPI  () { return fv(3.14159265f); }
  static float  FNAN () { return fv(Float.NaN); }
  static float  FPINF() { return fv(Float.POSITIVE_INFINITY); }
  static float  FNINF() { return fv(Float.NEGATIVE_INFINITY); }
  static float  FPZ  () { return fv(0.0f); }
  static float  FNZ  () { return fv(-0.0f); }
  static float  FMAX () { return fv(Float.MAX_VALUE); }
  static float  FMIN () { return fv(Float.MIN_VALUE); }
  static float  FMINN() { return fv(Float.intBitsToFloat(0x00800000)); } // smallest normal

  static double D1   () { return dv(1.0); }
  static double D2   () { return dv(2.0); }
  static double D1P5 () { return dv(1.5); }
  static double DPI  () { return dv(3.141592653589793); }
  static double DNAN () { return dv(Double.NaN); }
  static double DPINF() { return dv(Double.POSITIVE_INFINITY); }
  static double DNINF() { return dv(Double.NEGATIVE_INFINITY); }
  static double DPZ  () { return dv(0.0); }
  static double DNZ  () { return dv(-0.0); }
  static double DMAX () { return dv(Double.MAX_VALUE); }
  static double DMIN () { return dv(Double.MIN_VALUE); }
  static double DMINN() { return dv(Double.longBitsToDouble(0x0010000000000000L)); } // smallest normal

  static void floatArith() {
    // fadd
    outf("fadd.1.2",         F1() + F2());
    outf("fadd.nan.1",       FNAN() + F1());
    outf("fadd.1.nan",       F1() + FNAN());
    outf("fadd.pinf.1",      FPINF() + F1());
    outf("fadd.ninf.1",      FNINF() + F1());
    outf("fadd.pinf.ninf",   FPINF() + FNINF());
    outf("fadd.pzero.nzero", FPZ() + FNZ());
    outf("fadd.nzero.nzero", FNZ() + FNZ());
    outf("fadd.max.max",     FMAX() + FMAX());
    outf("fadd.min.min",     FMIN() + FMIN());
    outf("fadd.minn.minn",   FMINN() + FMINN());

    // fsub
    outf("fsub.2.1",         F2() - F1());
    outf("fsub.nan.1",       FNAN() - F1());
    outf("fsub.pinf.pinf",   FPINF() - FPINF());
    outf("fsub.pzero.pzero", FPZ() - FPZ());
    outf("fsub.pzero.nzero", FPZ() - FNZ());
    outf("fsub.nzero.pzero", FNZ() - FPZ());
    outf("fsub.nzero.nzero", FNZ() - FNZ());

    // fmul
    outf("fmul.2.1p5",       F2() * F1P5());
    outf("fmul.nan.1",       FNAN() * F1());
    outf("fmul.pinf.pzero",  FPINF() * FPZ());
    outf("fmul.pzero.nzero", FPZ() * FNZ());
    outf("fmul.nzero.nzero", FNZ() * FNZ());
    outf("fmul.max.2",       FMAX() * F2());
    outf("fmul.min.min",     FMIN() * FMIN());
    outf("fmul.neg1.nzero",  fv(-1.0f) * FNZ());

    // fdiv
    outf("fdiv.3.2",         fv(3.0f) / F2());
    outf("fdiv.nan.1",       FNAN() / F1());
    outf("fdiv.1.pzero",     F1() / FPZ());
    outf("fdiv.1.nzero",     F1() / FNZ());
    outf("fdiv.pzero.pzero", FPZ() / FPZ());
    outf("fdiv.nzero.pzero", FNZ() / FPZ());
    outf("fdiv.pinf.pinf",   FPINF() / FPINF());
    outf("fdiv.pzero.1",     FPZ() / F1());
    outf("fdiv.nzero.1",     FNZ() / F1());
    outf("fdiv.min.max",     FMIN() / FMAX());

    // frem
    outf("frem.5.3",         fv(5.0f) % fv(3.0f));
    outf("frem.nan.1",       FNAN() % F1());
    outf("frem.pinf.1",      FPINF() % F1());
    outf("frem.1.pzero",     F1() % FPZ());
    outf("frem.neg5.3",      fv(-5.0f) % fv(3.0f));

    // fneg
    outf("fneg.1",           -F1());
    outf("fneg.nan",         -FNAN());
    outf("fneg.pinf",        -FPINF());
    outf("fneg.ninf",        -FNINF());
    outf("fneg.pzero",       -FPZ());
    outf("fneg.nzero",       -FNZ());
  }

  static void doubleArith() {
    // dadd
    outd("dadd.1.2",         D1() + D2());
    outd("dadd.nan.1",       DNAN() + D1());
    outd("dadd.pinf.ninf",   DPINF() + DNINF());
    outd("dadd.pzero.nzero", DPZ() + DNZ());
    outd("dadd.nzero.nzero", DNZ() + DNZ());
    outd("dadd.max.max",     DMAX() + DMAX());
    outd("dadd.min.min",     DMIN() + DMIN());

    // dsub
    outd("dsub.2.1",         D2() - D1());
    outd("dsub.nan.1",       DNAN() - D1());
    outd("dsub.pinf.pinf",   DPINF() - DPINF());
    outd("dsub.pzero.nzero", DPZ() - DNZ());
    outd("dsub.nzero.pzero", DNZ() - DPZ());
    outd("dsub.nzero.nzero", DNZ() - DNZ());

    // dmul
    outd("dmul.2.1p5",       D2() * D1P5());
    outd("dmul.nan.1",       DNAN() * D1());
    outd("dmul.pinf.pzero",  DPINF() * DPZ());
    outd("dmul.pzero.nzero", DPZ() * DNZ());
    outd("dmul.nzero.nzero", DNZ() * DNZ());
    outd("dmul.max.2",       DMAX() * D2());
    outd("dmul.min.min",     DMIN() * DMIN());
    outd("dmul.neg1.nzero",  dv(-1.0) * DNZ());

    // ddiv
    outd("ddiv.3.2",         dv(3.0) / D2());
    outd("ddiv.nan.1",       DNAN() / D1());
    outd("ddiv.1.pzero",     D1() / DPZ());
    outd("ddiv.1.nzero",     D1() / DNZ());
    outd("ddiv.pzero.pzero", DPZ() / DPZ());
    outd("ddiv.pinf.pinf",   DPINF() / DPINF());

    // drem
    outd("drem.5.3",         dv(5.0) % dv(3.0));
    outd("drem.pinf.1",      DPINF() % D1());
    outd("drem.1.pzero",     D1() % DPZ());

    // dneg
    outd("dneg.1",           -D1());
    outd("dneg.nan",         -DNAN());
    outd("dneg.pinf",        -DPINF());
    outd("dneg.pzero",       -DPZ());
    outd("dneg.nzero",       -DNZ());
  }

  static void conversions() {
    // f2i: NaN→0, overflow→MAX_VALUE/MIN_VALUE
    outi("f2i.1",       (int) F1());
    outi("f2i.1p9",     (int) fv(1.9f));
    outi("f2i.neg1p9",  (int) fv(-1.9f));
    outi("f2i.nan",     (int) FNAN());
    outi("f2i.pinf",    (int) FPINF());
    outi("f2i.ninf",    (int) FNINF());
    outi("f2i.max",     (int) FMAX());
    outi("f2i.2e31",    (int) fv(2.0e31f));
    outi("f2i.neg2e31", (int) fv(-2.0e31f));

    // f2l: NaN→0, overflow→MAX/MIN
    outl("f2l.1",       (long) F1());
    outl("f2l.nan",     (long) FNAN());
    outl("f2l.pinf",    (long) FPINF());
    outl("f2l.ninf",    (long) FNINF());
    outl("f2l.max",     (long) FMAX());
    outl("f2l.negmax",  (long) fv(-Float.MAX_VALUE));

    // f2d: widening; NaN must stay NaN with canonical bits
    outd("f2d.1",       (double) F1());
    outd("f2d.nan",     (double) FNAN());
    outd("f2d.pinf",    (double) FPINF());
    outd("f2d.pzero",   (double) FPZ());
    outd("f2d.nzero",   (double) FNZ());
    outd("f2d.min",     (double) FMIN());
    outd("f2d.max",     (double) FMAX());

    // d2f: narrowing; NaN must stay NaN with canonical float bits
    outf("d2f.1",       (float) D1());
    outf("d2f.nan",     (float) DNAN());
    outf("d2f.pinf",    (float) DPINF());
    outf("d2f.pzero",   (float) DPZ());
    outf("d2f.nzero",   (float) DNZ());
    outf("d2f.max",     (float) DMAX());
    outf("d2f.min",     (float) DMIN());

    // d2i
    outi("d2i.1",       (int) D1());
    outi("d2i.1p9",     (int) dv(1.9));
    outi("d2i.nan",     (int) DNAN());
    outi("d2i.pinf",    (int) DPINF());
    outi("d2i.ninf",    (int) DNINF());
    outi("d2i.2e31",    (int) dv(2.0e31));

    // d2l
    outl("d2l.1",       (long) D1());
    outl("d2l.nan",     (long) DNAN());
    outl("d2l.pinf",    (long) DPINF());
    outl("d2l.ninf",    (long) DNINF());
    outl("d2l.2e63",    (long) dv(2.0e63));

    // i2f / i2d
    outf("i2f.0",       (float) iv(0));
    outf("i2f.1",       (float) iv(1));
    outf("i2f.maxint",  (float) iv(Integer.MAX_VALUE));
    outf("i2f.minint",  (float) iv(Integer.MIN_VALUE));
    outd("i2d.maxint",  (double) iv(Integer.MAX_VALUE));
    outd("i2d.minint",  (double) iv(Integer.MIN_VALUE));

    // l2f / l2d
    outf("l2f.1",       (float) lv(1L));
    outf("l2f.maxlong", (float) lv(Long.MAX_VALUE));
    outf("l2f.minlong", (float) lv(Long.MIN_VALUE));
    outd("l2d.maxlong", (double) lv(Long.MAX_VALUE));
    outd("l2d.minlong", (double) lv(Long.MIN_VALUE));
  }

  static void comparisons() {
    float fa = F1(), fb = F2(), fnan = FNAN();
    double da = D1(), db = D2(), dnan = DNAN();

    // fcmpl / fcmpg via Java ternary (compiler emits the appropriate opcode)
    outi("fcmp.1.lt.2",    fa < fb ? 1 : 0);
    outi("fcmp.2.gt.1",    fb > fa ? 1 : 0);
    outi("fcmp.1.eq.1",    fa == fa ? 1 : 0);
    outi("fcmp.nan.lt.1",  fnan < fa ? 1 : 0);
    outi("fcmp.nan.gt.1",  fnan > fa ? 1 : 0);
    outi("fcmp.nan.eq.nan",fnan == fnan ? 1 : 0);
    outi("fcmp.nan.ne.nan",fnan != fnan ? 1 : 0);

    // dcmpl / dcmpg
    outi("dcmp.1.lt.2",    da < db ? 1 : 0);
    outi("dcmp.2.gt.1",    db > da ? 1 : 0);
    outi("dcmp.1.eq.1",    da == da ? 1 : 0);
    outi("dcmp.nan.lt.1",  dnan < da ? 1 : 0);
    outi("dcmp.nan.gt.1",  dnan > da ? 1 : 0);
    outi("dcmp.nan.eq.nan",dnan == dnan ? 1 : 0);
    outi("dcmp.nan.ne.nan",dnan != dnan ? 1 : 0);
  }

  static void arrayRoundtrip() {
    // fastore / faload: edge cases must survive array round-trip with correct bits
    float[] fa = new float[6];
    fa[0] = FNAN();  fa[1] = FPINF(); fa[2] = FNINF();
    fa[3] = FPZ();   fa[4] = FNZ();   fa[5] = FMIN();
    outf("faload.nan",   fa[0]);
    outf("faload.pinf",  fa[1]);
    outf("faload.ninf",  fa[2]);
    outf("faload.pzero", fa[3]);
    outf("faload.nzero", fa[4]);
    outf("faload.min",   fa[5]);

    // dastore / daload
    double[] da = new double[6];
    da[0] = DNAN();  da[1] = DPINF(); da[2] = DNINF();
    da[3] = DPZ();   da[4] = DNZ();   da[5] = DMIN();
    outd("daload.nan",   da[0]);
    outd("daload.pinf",  da[1]);
    outd("daload.ninf",  da[2]);
    outd("daload.pzero", da[3]);
    outd("daload.nzero", da[4]);
    outd("daload.min",   da[5]);
  }

  public static void main(String[] args) {
    floatArith();
    doubleArith();
    conversions();
    comparisons();
    arrayRoundtrip();
    System.out.println("FloatConformanceVector:done");
  }
}
