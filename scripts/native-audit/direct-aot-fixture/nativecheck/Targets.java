package nativecheck;

public final class Targets {
    private final Object value;
    public Targets(Object value) { this.value = value; }
    public static int leaf(int x) { return x * 3 + 7; }
    public static int chain(int x) { return leaf(x) + leaf(x + 1); }
    public static int loop(int n) { int sum = 0; for (int i = 0; i < n; i++) sum += leaf(i); return sum; }
    public static long recursive(int n) { return n <= 1 ? 1 : n * recursive(n - 1); }
    public static int branch(boolean enabled, boolean hovered) { int i = 1; if (!enabled) i = 0; else if (hovered) i = 2; return i; }
    public static double slope(double x, double y, double x2, double y2) { double dx=x2-x,dy=y2-y; return dx==0 || dy==0 ? 0 : dy/dx; }
    public final Object get() { return value; }
    private Object privateGet() { return value; }
    public Object privateChain() { return privateGet(); }
    public static Object instanceChain(Targets target) { return target.get(); }
    public static Object nullable(Targets target) { try { return target.get(); } catch (NullPointerException expected) { return "null-caught"; } }
    public static int division(int a, int b) { return a/b; }
    public static int catchDivision(int a,int b) { try { return division(a,b); } catch(ArithmeticException e) { return -77; } }
    public static int sum(int[] array) { int total=0; for(int i=0;i<array.length;i++) total+=array[i]; return total; }
    public static Object[] objects(Object value) { Object[] array=new Object[2]; array[0]=value; array[1]=value; return array; }
    public static boolean referenceIdentity(Targets a, Targets b) { return a.get() == b.get(); }
    public static int virtualCall(Base value) { return value.read(); }
    public static int crossClass(int x) { return Other.plus(x); }
    public static long shifts(long value,int amount) { return (value << amount) ^ (value >>> amount) ^ (value >> amount); }
    public static int charArray(char value) { char[] values=new char[2]; values[1]=value; return values[1]; }
    public static int shortArray(short value) { short[] values=new short[2]; values[1]=value; return values[1]; }
    public static boolean booleanArray(boolean value) { boolean[] values=new boolean[2]; values[1]=value; return values[1]; }
    public static double floatingArrays(float a,double b) { float[] x=new float[1]; double[] y=new double[1]; x[0]=a; y[0]=b; return x[0]+y[0]; }
    public static int nestedArray() { int[][] a=new int[2][3];a[1][2]=71;return a[1][2]; }
    public static int nullArray(int[] a) { try { return a.length; } catch(NullPointerException expected) { return -9; } }
    public static Object nullField(Targets a) { try { return a.value; } catch(NullPointerException expected) { return "field-null"; } }
    public static boolean instanceOf(Object value) { return value instanceof Targets; }
    public static int byteLoop(byte count) { int sum=0;for(int i=0;i<count;i++)sum+=i;return sum; }
    public static Throwable caughtIdentity(Throwable value) { try { throw value; } catch(Throwable caught) { chain(5); return caught; } }
    public static int initializationCycle() { return CycleA.read()*10+CycleB.read(); }
    public static class Base { public int read() { return 4; } }
    public static final class Derived extends Base { public int read() { return 9; } }
    public static final class Other { static int value=InitTracker.initialize(); public static int plus(int x) { return x+value; } }
    public static final class CycleA { static int value=CycleB.read()+1; public static int read() { return value; } }
    public static final class CycleB { static int value=CycleA.read()+1; public static int read() { return value; } }
}
