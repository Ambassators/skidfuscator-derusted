package selectivecheck;

public class Hot {
    static { Tracker.initialized++; }
    public static int compute(int x) { return twice(x) + 1; }
    private static int twice(int x) { return x * 2; }
    public final int finalCompute(int x) { return compute(x) + 3; }
    public int virtualCompute(int x) { return x; }
    public static int throwing(int x) { if (x < 0) throw new IllegalArgumentException(); return x; }
    public static Object identity(Object object) { return object; }
    public static int unused(int x) { return x + 100; }
}
class Tracker { static int initialized; }
