package sdk.integrity;

import org.junit.jupiter.api.Test;
import sdk.LongHashFunction;
import sdk.Tamper;
import java.io.InputStream;
import static org.junit.jupiter.api.Assertions.*;

class TamperStrictTest {
    public static final class Fixture { }

    @Test void nullAndUnreadableTargetsFailClosed() throws Exception {
        assertThrows(IllegalStateException.class, () -> Tamper.verify(null, 0L));
        final byte[] bytes;
        try (InputStream in = Fixture.class.getResourceAsStream("/" + Fixture.class.getName().replace('.', '/') + ".class")) {
            bytes = ArchiveIntegrity.readBounded(in, 1024 * 1024);
        }
        class OpaqueLoader extends ClassLoader {
            OpaqueLoader() { super(null); }
            Class<?> define() { return defineClass(Fixture.class.getName(), bytes, 0, bytes.length); }
            @Override public InputStream getResourceAsStream(String name) { return null; }
        }
        Class<?> opaque = new OpaqueLoader().define();
        assertThrows(IllegalStateException.class, () -> Tamper.verify(opaque, 0L));
    }

    @Test void readableTargetMustHaveTheCorrectHash() throws Exception {
        final byte[] bytes;
        try (InputStream in = Fixture.class.getResourceAsStream("/" + Fixture.class.getName().replace('.', '/') + ".class")) {
            bytes = ArchiveIntegrity.readBounded(in, 1024 * 1024);
        }
        long expected = LongHashFunction.xx3().hashBytes(bytes);
        assertDoesNotThrow(() -> Tamper.verify(Fixture.class, expected));
        assertThrows(IllegalStateException.class, () -> Tamper.verify(Fixture.class, expected ^ 1L));
    }
}
