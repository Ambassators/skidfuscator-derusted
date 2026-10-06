import java.io.PrintWriter;
import org.junit.platform.engine.TestExecutionResult;
import org.junit.platform.launcher.TestExecutionListener;
import org.junit.platform.launcher.TestIdentifier;
import org.junit.platform.launcher.core.LauncherDiscoveryRequestBuilder;
import org.junit.platform.launcher.core.LauncherFactory;
import org.junit.platform.launcher.listeners.SummaryGeneratingListener;
import static org.junit.platform.engine.discovery.DiscoverySelectors.*;

/** Standalone audit runner for environments where the Gradle daemon cannot start.
 * Requires the project's JUnit Platform runtime on the classpath. A skipped or
 * aborted check is reported and produces exit code 2, never a successful audit.
 */
public final class NativeVerificationRunner {
    private NativeVerificationRunner() { }

    public static void main(String[] args) {
        var request = LauncherDiscoveryRequestBuilder.request();
        if (args.length == 0) {
            request.selectors(selectPackage("dev.skidfuscator.nativeir"),
                    selectPackage("dev.skidfuscator.nativetoolchain"),
                    selectPackage("dev.skidfuscator.config"),
                    selectPackage("dev.skidfuscator.annotations"),
                    selectPackage("dev.skidfuscator.test.nativebackend"));
        } else {
            for (String name : args) request.selectors(selectClass(name));
        }
        var summaryListener = new SummaryGeneratingListener();
        var diagnostics = new TestExecutionListener() {
            @Override
            public void executionSkipped(TestIdentifier test, String reason) {
                System.out.println("SKIPPED " + test.getUniqueId() + ": " + reason);
            }
            @Override
            public void executionFinished(TestIdentifier test, TestExecutionResult result) {
                if (test.isTest() || result.getStatus() != TestExecutionResult.Status.SUCCESSFUL) {
                    System.out.println(result.getStatus() + " " + test.getUniqueId());
                    result.getThrowable().ifPresent(failure -> failure.printStackTrace(System.out));
                }
            }
        };
        LauncherFactory.create().execute(request.build(), summaryListener, diagnostics);
        var summary = summaryListener.getSummary();
        summary.printTo(new PrintWriter(System.out, true));
        summary.printFailuresTo(new PrintWriter(System.out, true));
        if (summary.getTotalFailureCount() != 0 || summary.getTestsFoundCount() == 0) {
            System.exit(1);
        }
        if (summary.getTestsAbortedCount() != 0 || summary.getTestsSkippedCount() != 0
                || summary.getContainersAbortedCount() != 0 || summary.getContainersSkippedCount() != 0) {
            System.exit(2);
        }
    }
}
