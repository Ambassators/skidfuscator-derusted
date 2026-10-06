package selectivecheck;

import java.util.function.IntUnaryOperator;

public class Targets {
    private final int offset;
    public Targets(int offset) { this.offset = constructorHelper(offset); }
    private static int constructorHelper(int x) { return x; }
    public static int nativeRoot(int x) { return privateTree(x) + new Targets(3).privateInstance(x); }
    private static int privateTree(int x) { return x <= 1 ? 1 : x * privateTree(x - 1); }
    private int privateInstance(int x) { return x + offset; }

    public static int useHot(int x) { return Hot.compute(x); }
    public static int useFinal(Hot hot, int x) { return hot.finalCompute(x); }
    public static int useVirtual(Hot hot, int x) { return hot.virtualCompute(x); }
    public static int catchHot(int x) {
        try { return Hot.throwing(x); } catch (IllegalArgumentException ex) { return 73; }
    }
    public static Object identity(Object object) { return Hot.identity(object); }
    public static int javaCaller(int x) { return shared(x); }
    public static int nativeCaller(int x) { return shared(x); }
    private static int shared(int x) { return x + 8; }
    public static IntUnaryOperator lambda() { return Targets::lambdaBody; }
    private static int lambdaBody(int x) { return x + 9; }
    private static int reflectMe(int x) { return x + 10; }
    @Deprecated private static int annotated(int x) { return x + 11; }
    private static synchronized int synchronizedBody(int x) { return x + 12; }
    public static int useRetained(int x) { return annotated(x) + synchronizedBody(x); }

    // Native lowering currently cannot type this array-clone owner. It must keep Java,
    // and its call to fallbackHelper must keep the helper's Java native declaration.
    public static int[] fallback(int[] values) { fallbackHelper(); return values.clone(); }
    private static void fallbackHelper() { }
}
