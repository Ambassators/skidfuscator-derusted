package sdk.integrity;

import org.junit.jupiter.api.Test;
import java.util.Arrays;
import java.util.Collections;
import java.util.Properties;
import static org.junit.jupiter.api.Assertions.*;

class JvmPolicyTest {
    @Test void debuggerFormsAreRejected() {
        for (String arg : Arrays.asList("-agentlib:jdwp=transport=dt_socket", "-agentlib:jdwp",
                "-Xrunjdwp:server=y", "-Xrunjdwp", "-AGENTLIB:JDWP=server=y")) {
            assertThrows(SecurityException.class,
                    () -> JvmPolicy.checkArguments(Collections.singletonList(arg), JvmPolicy.DENY_JDWP), arg);
        }
    }

    @Test void startupAgentsAreRejectedWithoutSubstringFalsePositives() {
        for (String arg : Arrays.asList("-javaagent:C:\\an agent.jar=options", "-agentpath:C:\\agent.dll",
                "-agentlib:instrument", "-Xrunhprof:cpu=samples")) {
            assertThrows(SecurityException.class,
                    () -> JvmPolicy.checkArguments(Collections.singletonList(arg), JvmPolicy.STRICT), arg);
        }
        assertDoesNotThrow(() -> JvmPolicy.checkArguments(Arrays.asList("-Xmx2g", "-Xdebug",
                "-Ddescription=-javaagent:not-a-real-option", "-Dserver.name=jdwp", "-Xverify:all"), JvmPolicy.STRICT));
    }

    @Test void unsafeVerificationAndClassLoadingOverridesAreRejected() {
        for (String arg : Arrays.asList("-noverify", "-Xverify:none", "-Xbootclasspath/a:extra.jar",
                "--patch-module=java.base=extra.jar", "--upgrade-module-path", "-Djava.system.class.loader=Other",
                "-Djava.ext.dirs=other", "-Djava.endorsed.dirs=other")) {
            assertThrows(SecurityException.class,
                    () -> JvmPolicy.checkArguments(Collections.singletonList(arg), JvmPolicy.DENY_UNSAFE_OVERRIDES), arg);
        }
    }

    @Test void managementConfigurationIsCheckedIndependentlyOfArgumentText() {
        Properties p = new Properties();
        p.setProperty("some.description", "com.sun.management.jmxremote");
        assertDoesNotThrow(() -> JvmPolicy.checkManagementProperties(p));
        p.setProperty("com.sun.management.jmxremote.port", "9999");
        assertThrows(SecurityException.class, () -> JvmPolicy.checkManagementProperties(p));
    }

    @Test void invalidPolicyBitsAndIntervalsFailRatherThanDisableProtection() {
        assertThrows(IllegalArgumentException.class, () -> JvmPolicy.validate(-1));
        assertThrows(IllegalArgumentException.class, () -> JvmPolicy.validate(128));
        assertThrows(IllegalArgumentException.class, () -> RuntimeGuard.validateInterval(0));
        assertThrows(IllegalArgumentException.class, () -> RuntimeGuard.validateInterval(300001));
        assertDoesNotThrow(() -> RuntimeGuard.validateInterval(1000));
        assertDoesNotThrow(() -> RuntimeGuard.validateInterval(300000));
    }

    @Test void explicitlyReducedBuildPolicyIsHonored() {
        assertDoesNotThrow(() -> JvmPolicy.checkArguments(Collections.singletonList("-javaagent:test.jar"), 0));
        assertDoesNotThrow(() -> JvmPolicy.checkArguments(Collections.singletonList("-agentlib:other"), JvmPolicy.DENY_JDWP));
        assertThrows(SecurityException.class, () -> JvmPolicy.checkArguments(null, JvmPolicy.STRICT));
    }
}
