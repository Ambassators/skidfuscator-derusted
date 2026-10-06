package nativecheck;
public final class InitTracker {
    public static int initialized;
    public static int initialize() { initialized++; return 13; }
}
