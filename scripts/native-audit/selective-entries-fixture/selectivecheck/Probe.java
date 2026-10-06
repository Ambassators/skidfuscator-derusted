package selectivecheck;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;

public class Probe {
    private static int checks;
    private static void check(boolean condition) { if (!condition) throw new AssertionError("check " + checks); checks++; }
    public static void main(String[] args) throws Exception {
        check(Tracker.initialized == 0);
        check(Targets.nativeRoot(4) == 31);
        check(Tracker.initialized == 0);
        check(Targets.useHot(4) == 9);
        check(Tracker.initialized == 1);
        check(Hot.compute(4) == 9);
        check(!Modifier.isNative(Hot.class.getDeclaredMethod("compute", int.class).getModifiers()));
        check(Targets.useFinal(new Hot(), 4) == 12);
        check(new Hot().finalCompute(4) == 12);
        check(Targets.useVirtual(new Hot() { public int virtualCompute(int x) { return x + 70; } }, 4) == 74);
        check(Targets.catchHot(-1) == 73);
        check(Targets.catchHot(5) == 5);
        try { Hot.throwing(-1); throw new AssertionError(); } catch (IllegalArgumentException expected) { checks++; }
        try { Targets.useFinal(null, 4); throw new AssertionError(); } catch (NullPointerException expected) { checks++; }
        Object object = new Object();
        check(Targets.identity(object) == object);
        check(Hot.identity(object) == object);
        check(Targets.javaCaller(4) == 12);
        check(Targets.nativeCaller(4) == 12);
        check(Targets.lambda().applyAsInt(4) == 13);
        Method reflected = Targets.class.getDeclaredMethod("reflectMe", int.class);
        reflected.setAccessible(true);
        check(((Integer) reflected.invoke(null, 4)) == 14);
        check(Targets.useRetained(4) == 31);
        check(Targets.fallback(new int[] {7})[0] == 7);
        check(Hot.unused(4) == 104);
        // Check removed names in Python's classfile audit, so literal reflection names
        // here cannot accidentally pin precisely the methods under test.
        System.out.println("SELECTIVE_ENTRIES passed=" + checks);
    }
}
