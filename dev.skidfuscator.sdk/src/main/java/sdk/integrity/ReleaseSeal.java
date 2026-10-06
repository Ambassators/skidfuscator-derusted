package sdk.integrity;

/** Replaced by ArchiveSealer after every bytecode/resource transformation. */
public final class ReleaseSeal {
    private ReleaseSeal() { }

    // Methods, not constant fields: javac must not inline the development values.
    public static boolean development() { return false; }
    public static String indexHash() { return ""; }
    public static int policy() { return 0; }
    public static long intervalMillis() { return 30000L; }
}
