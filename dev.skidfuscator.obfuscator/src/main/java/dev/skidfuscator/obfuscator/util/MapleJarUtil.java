package dev.skidfuscator.obfuscator.util;

import com.esotericsoftware.asm.Type;
import com.googlecode.d2j.node.DexFileNode;
import com.googlecode.d2j.reader.DexFileReader;
import dev.skidfuscator.obfuscator.Skidfuscator;
import dev.skidfuscator.obfuscator.transform.impl.integrity.RuntimeProtection;
import dev.skidfuscator.obfuscator.creator.SkidASMFactory;
import dev.skidfuscator.obfuscator.creator.SkidFlowGraphDumper;
import dev.skidfuscator.obfuscator.creator.SkidLibASMFactory;
import dev.skidfuscator.obfuscator.io.dex.DexJarDownloader;
import dev.skidfuscator.obfuscator.phantom.jphantom.PhantomJarDownloader;
import dev.skidfuscator.obfuscator.phantom.jphantom.PhantomResolvingJarDumper;
import lombok.SneakyThrows;
import org.mapleir.app.service.ClassTree;
import org.mapleir.asm.ClassNode;
import org.mapleir.deob.PassGroup;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodTooLargeException;
import org.objectweb.asm.commons.ClassRemapper;
import org.topdank.byteengineer.commons.asm.ASMFactory;
import org.topdank.byteengineer.commons.data.JarClassData;
import org.topdank.byteengineer.commons.data.JarInfo;
import org.topdank.byteio.in.MultiJarDownloader;
import org.topdank.byteio.in.SingleJarDownloader;
import org.topdank.byteio.in.SingleJmodDownloader;

import java.io.*;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

/**
 * @author Ghast
 * @since 12/12/2020
 * HideMySkewnessCheckObfuscator © 2020
 */
public class MapleJarUtil {

    public MapleJarUtil() {
    }

    public static void dumpJar(Skidfuscator skidfuscator, PassGroup masterGroup, String outputFile) throws IOException {
        RuntimeProtection.validate(skidfuscator);
        final java.nio.file.Path destination = new File(outputFile).toPath().toAbsolutePath();
        java.nio.file.Files.createDirectories(destination.getParent());
        final java.nio.file.Path stage = java.nio.file.Files.createTempFile(destination.getParent(), ".skid-output-", ".jar");
        try {
            dumpJarContents(skidfuscator, masterGroup, stage.toString());
            RuntimeProtection.seal(skidfuscator, stage.toFile());
            try {
                java.nio.file.Files.move(stage, destination, java.nio.file.StandardCopyOption.ATOMIC_MOVE,
                        java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            } catch (java.nio.file.AtomicMoveNotSupportedException unsupported) {
                java.nio.file.Files.move(stage, destination, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            java.nio.file.Files.deleteIfExists(stage);
        }
    }

    private static void dumpJarContents(Skidfuscator skidfuscator, PassGroup masterGroup, String outputFile) throws IOException {
        // Output-only Mixin protocol envelopes: retain transformed initializer bodies,
        // but never send their line-marked transplant wrappers through body passes.
        dev.skidfuscator.obfuscator.compatibility.MixinInitializerBridge.apply(skidfuscator);
        // Tamper protection materialises a cross-class integrity mesh at output time,
        // which requires buffering every class's final bytes before stamping (a target
        // must be frozen before the holder that hashes it). It needs the SDK helper to
        // ship. When off, the legacy single-pass streaming dump below runs unchanged.
        final boolean tamperRequested = skidfuscator.getConfig().getBoolean("tamperProtection.enabled", false);
        if (tamperRequested) {
            final boolean sdkEnabled = skidfuscator.getConfig().getBoolean("sdk.enabled", true);
            // fileCrasher appends a trailing slash to class entries, so the runtime
            // resource read would never find the class and every check would be inert.
            final boolean fileCrasher = skidfuscator.getConfig().getBoolean("fileCrasher.enabled", false);
            if (sdkEnabled && !fileCrasher) {
                new dev.skidfuscator.obfuscator.phantom.jphantom.TamperJarDumper(
                        skidfuscator,
                        skidfuscator.getJarContents(),
                        skidfuscator.getClassSource()
                ).dump(new File(outputFile));
                return;
            }
            throw new IOException("Requested tamper protection cannot be emitted with this configuration");
        }

        (new PhantomResolvingJarDumper(skidfuscator, skidfuscator.getJarContents(), skidfuscator.getClassSource()) {

            private Map<String, JarClassData> jarClassDataMap = skidfuscator
                    .getJarContents()
                    .getClassContents()
                    .namedMap();

            private ASMFactory<ClassNode> factory = new SkidASMFactory(skidfuscator);

            @Override
            public int dumpClass(JarOutputStream out, JarClassData classData) throws IOException {
                final ClassNode cn = classData.getClassNode();
                for (org.objectweb.asm.tree.MethodNode method : cn.node.methods) {
                    method.localVariables = null;
                }
                final boolean exempt = !cn.isVirtual() && skidfuscator.getExemptAnalysis().isExempt(cn);
                final byte[] bytes;
                try {
                    final int flags = exempt ? 0 : (SkidFlowGraphDumper.TEST_COMPUTE
                            ? ClassWriter.COMPUTE_MAXS : ClassWriter.COMPUTE_FRAMES);
                    final ClassWriter writer = buildClassWriter(skidfuscator.getClassSource().getClassTree(), flags);
                    cn.node.accept(new ClassRemapper(writer, skidfuscator.getClassRemapper()));
                    bytes = RuntimeProtection.instrument(skidfuscator, cn, writer.toByteArray());
                } catch (Exception failure) {
                    // Original-class/MAXS fallbacks are not safe after cross-class rewrites.
                    throw new IOException("Unable to serialize transformed class " + cn.getName()
                            + "; refusing to publish partial or unverified bytecode", failure);
                }
                String path = new org.objectweb.asm.ClassReader(bytes).getClassName() + ".class";
                if (skidfuscator.getConfig().getBoolean("fileCrasher.enabled", false)) {
                    path += "/";
                }
                // Serialize before opening an entry, so a failure cannot create an empty class.
                out.putNextEntry(new JarEntry(path));
                out.write(bytes);
                out.closeEntry();
                return 1;
            }
        }).dump(new File(outputFile));
    }

    @SneakyThrows
    public static MultiJarDownloader<ClassNode> importJars(File... file) {
        final JarInfo[] jarInfos = new JarInfo[file.length];

        for (int i = 0; i < file.length; i++) {
            jarInfos[i] = new JarInfo(file[i]);
        }

        MultiJarDownloader<ClassNode> dl = new MultiJarDownloader<>(jarInfos);
        dl.download();

        return dl;
    }

    @SneakyThrows
    public static SingleJarDownloader<ClassNode> importJar(File file, Skidfuscator skidfuscator) {
        SingleJarDownloader<ClassNode> dl = new SingleJarDownloader<>(
                new SkidLibASMFactory(skidfuscator),
                new JarInfo(file)
        );
        dl.download();

        return dl;
    }

    @SneakyThrows
    public static SingleJmodDownloader<ClassNode> importJmod(File file) {
        SingleJmodDownloader<ClassNode> dl = new SingleJmodDownloader<>(new JarInfo(file));
        dl.download();

        return dl;
    }

    @SneakyThrows
    public static PhantomJarDownloader<ClassNode> importPhantomJar(File file, Skidfuscator skidfuscator) {
        PhantomJarDownloader<ClassNode> dl = new PhantomJarDownloader<>(
                skidfuscator,
                new SkidASMFactory(skidfuscator),
                new JarInfo(file)
        );

        dl.download();

        return dl;
    }

    @SneakyThrows
    public static DexJarDownloader<ClassNode> importDex(File file, Skidfuscator skidfuscator) {
        DexFileReader reader = new DexFileReader(file);
        DexFileNode node = new DexFileNode();
        reader.accept(node);

        DexJarDownloader<ClassNode> dl = new DexJarDownloader<>(
                skidfuscator,
                new SkidASMFactory(skidfuscator),
                new JarInfo(file)
        );

        dl.download();

        return dl;
    }

}
