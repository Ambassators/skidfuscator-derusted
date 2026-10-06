package sdk.integrity;

import java.lang.management.ManagementFactory;
import java.lang.management.PlatformManagedObject;
import java.lang.reflect.Method;
import java.util.List;
import java.util.Locale;
import java.util.Properties;

/** Documented launch-policy checks, not a claim to block an OS administrator or a modified JVM. */
public final class JvmPolicy {
    public static final int DENY_JDWP = 1;
    public static final int DENY_JAVA_AGENTS = 2;
    public static final int DENY_NATIVE_AGENTS = 4;
    public static final int REQUIRE_ATTACH_DISABLED = 8;
    public static final int DENY_REMOTE_JMX = 16;
    public static final int DENY_OOM_HEAP_DUMP = 32;
    public static final int DENY_UNSAFE_OVERRIDES = 64;
    public static final int STRICT = 127;

    private JvmPolicy() { }

    public static void validate(int policy) {
        if (policy < 0 || (policy & ~STRICT) != 0) throw new IllegalArgumentException("Unknown JVM policy bits: " + policy);
    }

    public static void enforce(int policy) {
        validate(policy);
        checkArguments(ManagementFactory.getRuntimeMXBean().getInputArguments(), policy);
        if ((policy & DENY_REMOTE_JMX) != 0) checkManagementProperties(System.getProperties());
        if ((policy & REQUIRE_ATTACH_DISABLED) != 0 && !vmBoolean("DisableAttachMechanism")) {
            throw new SecurityException("[integrity] Launch this release with -XX:+DisableAttachMechanism");
        }
        if ((policy & DENY_OOM_HEAP_DUMP) != 0 && vmBoolean("HeapDumpOnOutOfMemoryError")) {
            throw new SecurityException("[integrity] Launch this release with -XX:-HeapDumpOnOutOfMemoryError");
        }
    }

    /** The actual MXBean arguments include options supplied through JAVA_TOOL_OPTIONS. */
    public static void checkArguments(List<String> arguments, int policy) {
        validate(policy);
        if (arguments == null) throw new SecurityException("[integrity] JVM arguments unavailable");
        for (String argument : arguments) {
            if (argument == null) throw new SecurityException("[integrity] Invalid JVM argument");
            String arg = argument.toLowerCase(Locale.ROOT);
            boolean jdwp = arg.equals("-agentlib:jdwp") || arg.startsWith("-agentlib:jdwp=")
                    || arg.equals("-xrunjdwp") || arg.startsWith("-xrunjdwp:");
            if ((policy & DENY_JDWP) != 0 && jdwp) reject("JDWP debugger is not permitted in this release");
            if ((policy & DENY_JAVA_AGENTS) != 0 && arg.startsWith("-javaagent:")) {
                reject("Java startup agents are not permitted in this release");
            }
            if ((policy & DENY_NATIVE_AGENTS) != 0 && (arg.startsWith("-agentpath:")
                    || arg.startsWith("-agentlib:") || arg.startsWith("-xrun"))) {
                reject("Native startup agents are not permitted in this release");
            }
            if ((policy & DENY_UNSAFE_OVERRIDES) != 0 && (arg.equals("-noverify")
                    || arg.equals("-xverify:none") || arg.startsWith("-xbootclasspath")
                    || arg.equals("--patch-module") || arg.startsWith("--patch-module=")
                    || arg.equals("--upgrade-module-path") || arg.startsWith("--upgrade-module-path=")
                    || arg.startsWith("-djava.system.class.loader=")
                    || arg.startsWith("-djava.endorsed.dirs=") || arg.startsWith("-djava.ext.dirs="))) {
                reject("Unsafe JVM class-loading/verification override is not permitted");
            }
        }
    }

    public static void checkManagementProperties(Properties properties) {
        if (properties == null) reject("JVM management configuration unavailable");
        for (String name : properties.stringPropertyNames()) {
            if (name.equals("com.sun.management.jmxremote") || name.startsWith("com.sun.management.jmxremote.")) {
                reject("Remote JVM management is not permitted in this release");
            }
        }
    }

    /** Query effective HotSpot flags; presence of a command-line string alone is not sufficient. */
    @SuppressWarnings({"unchecked", "rawtypes"})
    private static boolean vmBoolean(String option) {
        try {
            Class<?> beanType = Class.forName("com.sun.management.HotSpotDiagnosticMXBean", false, null);
            Object bean = ManagementFactory.getPlatformMXBean((Class<? extends PlatformManagedObject>) beanType);
            if (bean == null) throw new IllegalStateException("HotSpot diagnostic bean unavailable");
            Method getOption = beanType.getMethod("getVMOption", String.class);
            Object vmOption = getOption.invoke(bean, option);
            String value = (String) vmOption.getClass().getMethod("getValue").invoke(vmOption);
            if (!"true".equals(value) && !"false".equals(value)) throw new IllegalStateException("Non-boolean VM option");
            return Boolean.parseBoolean(value);
        } catch (ReflectiveOperationException | RuntimeException e) {
            throw new SecurityException("[integrity] Cannot verify " + option + "; this policy requires a supported HotSpot JVM", e);
        }
    }

    private static void reject(String reason) { throw new SecurityException("[integrity] " + reason); }
}
