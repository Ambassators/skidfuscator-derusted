package dev.skidfuscator.obfuscator.nativebackend.runtime;

import dev.skidfuscator.nativetoolchain.NativeTarget;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Label;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.GeneratorAdapter;
import org.objectweb.asm.commons.Method;

import java.util.Locale;
import java.util.Map;
import java.util.Objects;

/** Generates a dependency-free Java 8 loader for any subset of the six native targets. */
public final class NativeLoaderGenerator {
    private static final Type OBJECT = Type.getType(Object.class);
    private static final Type CLASS = Type.getType(Class.class);
    private static final Type SYSTEM = Type.getType(System.class);
    private static final Type STRING = Type.getType(String.class);
    private static final Type LOCALE = Type.getType(Locale.class);
    private static final Type INPUT = Type.getType(java.io.InputStream.class);
    private static final Type OUTPUT = Type.getType(java.io.ByteArrayOutputStream.class);
    private static final Type FILE = Type.getType(java.io.File.class);
    private static final Type FILE_OUTPUT = Type.getType(java.io.FileOutputStream.class);
    private static final Type FILE_DESCRIPTOR = Type.getType(java.io.FileDescriptor.class);
    private static final Type FILES = Type.getType(java.nio.file.Files.class);
    private static final Type PATH = Type.getType(java.nio.file.Path.class);
    private static final Type FILE_ATTRIBUTE = Type.getType(java.nio.file.attribute.FileAttribute.class);
    private static final Type COPY_OPTION = Type.getType(java.nio.file.CopyOption.class);
    private static final Type STANDARD_COPY_OPTION = Type.getType(java.nio.file.StandardCopyOption.class);
    private static final Type MESSAGE_DIGEST = Type.getType(java.security.MessageDigest.class);
    private static final Type THROWABLE = Type.getType(Throwable.class);
    private static final Type LINK_ERROR = Type.getType(UnsatisfiedLinkError.class);
    private static final Type IO_EXCEPTION = Type.getType(java.io.IOException.class);

    public GeneratedLoader generate(final NativeLoaderSpec spec) {
        Objects.requireNonNull(spec, "spec");
        final Type owner = Type.getObjectType(spec.internalName());
        final ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        writer.visit(Opcodes.V1_8,
                Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SUPER | Opcodes.ACC_SYNTHETIC,
                spec.internalName(), null, "java/lang/Object", null);
        writer.visitField(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_VOLATILE,
                "loaded", "Z", null, null).visitEnd();
        constructor(writer);
        bindingMethods(writer, owner);
        readFully(writer);
        sha256(writer);
        normalizePlatform(writer);
        lookup(writer, spec.libraries(), Lookup.RESOURCE);
        lookup(writer, spec.libraries(), Lookup.DIGEST);
        lookup(writer, spec.libraries(), Lookup.FILE_NAME);
        lookupSize(writer, spec.libraries());
        ensureLoaded(writer, owner, spec);
        writer.visitEnd();
        return new GeneratedLoader(spec.internalName(), writer.toByteArray());
    }

    private static void bindingMethods(final ClassWriter writer, final Type owner) {
        final Type set = Type.getType(java.util.Set.class);
        final Type hashSet = Type.getType(java.util.HashSet.class);
        writer.visitField(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL,
                "bound", set.getDescriptor(), null, null).visitEnd();
        GeneratorAdapter initializer = new GeneratorAdapter(Opcodes.ACC_STATIC,
                new Method("<clinit>", "()V"), null, null, writer);
        initializer.newInstance(hashSet);
        initializer.dup();
        initializer.invokeConstructor(hashSet, new Method("<init>", "()V"));
        initializer.putStatic(owner, "bound", set);
        initializer.returnValue();
        initializer.endMethod();
        writer.visitMethod(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_NATIVE,
                "bind", "(Ljava/lang/Class;Ljava/lang/String;)V", null, null).visitEnd();
        // Register only the class whose initializer is actually running. Loading
        // every owner from JNI_OnLoad changes initialization order and re-enters
        // the loader before the library has finished loading.
        GeneratorAdapter method = new GeneratorAdapter(
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_SYNCHRONIZED,
                new Method("ensureBound", "(Ljava/lang/Class;)V"), null, null, writer);
        method.invokeStatic(owner, new Method("ensureLoaded", "()V"));
        method.getStatic(owner, "bound", set);
        method.loadArg(0);
        method.invokeInterface(set, new Method("contains", "(Ljava/lang/Object;)Z"));
        final Label bind = method.newLabel();
        method.ifZCmp(GeneratorAdapter.EQ, bind);
        method.returnValue();
        method.mark(bind);
        method.loadArg(0);
        method.loadArg(0);
        method.invokeVirtual(CLASS, new Method("getName", "()Ljava/lang/String;"));
        method.invokeStatic(owner, new Method("bind", "(Ljava/lang/Class;Ljava/lang/String;)V"));
        method.getStatic(owner, "bound", set);
        method.loadArg(0);
        method.invokeInterface(set, new Method("add", "(Ljava/lang/Object;)Z"));
        method.pop();
        method.returnValue();
        method.endMethod();
    }

    private static void constructor(final ClassWriter writer) {
        final GeneratorAdapter method = new GeneratorAdapter(Opcodes.ACC_PRIVATE,
                new Method("<init>", "()V"), null, null, writer);
        method.loadThis();
        method.invokeConstructor(OBJECT, new Method("<init>", "()V"));
        method.returnValue();
        method.endMethod();
    }

    private static void readFully(final ClassWriter writer) {
        final GeneratorAdapter method = new GeneratorAdapter(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC,
                new Method("readFully", "(Ljava/io/InputStream;I)[B"), null,
                new Type[]{THROWABLE}, writer);
        final int buffer = method.newLocal(Type.getType(byte[].class));
        final int offset = method.newLocal(Type.INT_TYPE);
        final int count = method.newLocal(Type.INT_TYPE);
        final int failure = method.newLocal(THROWABLE);
        method.loadArg(1);
        method.newArray(Type.BYTE_TYPE);
        method.storeLocal(buffer);
        method.push(0);
        method.storeLocal(offset);
        final Label start = method.mark();
        final Label loop = method.mark();
        method.loadLocal(offset);
        method.loadArg(1);
        final Label complete = method.newLabel();
        method.ifICmp(GeneratorAdapter.GE, complete);
        method.loadArg(0);
        method.loadLocal(buffer);
        method.loadLocal(offset);
        method.loadArg(1);
        method.loadLocal(offset);
        method.math(GeneratorAdapter.SUB, Type.INT_TYPE);
        method.invokeVirtual(INPUT, new Method("read", "([BII)I"));
        method.storeLocal(count);
        method.loadLocal(count);
        final Label positive = method.newLabel();
        method.ifZCmp(GeneratorAdapter.GT, positive);
        method.newInstance(IO_EXCEPTION);
        method.dup();
        method.push("Embedded native resource is truncated");
        method.invokeConstructor(IO_EXCEPTION, new Method("<init>", "(Ljava/lang/String;)V"));
        method.throwException();
        method.mark(positive);
        method.loadLocal(count);
        method.loadLocal(offset);
        method.math(GeneratorAdapter.ADD, Type.INT_TYPE);
        method.storeLocal(offset);
        method.goTo(loop);
        method.mark(complete);
        method.loadArg(0);
        method.invokeVirtual(INPUT, new Method("read", "()I"));
        method.push(-1);
        final Label exact = method.newLabel();
        method.ifICmp(GeneratorAdapter.EQ, exact);
        method.newInstance(IO_EXCEPTION);
        method.dup();
        method.push("Embedded native resource exceeds its authenticated size");
        method.invokeConstructor(IO_EXCEPTION, new Method("<init>", "(Ljava/lang/String;)V"));
        method.throwException();
        method.mark(exact);
        method.loadArg(0);
        method.invokeVirtual(INPUT, new Method("close", "()V"));
        method.loadLocal(buffer);
        method.returnValue();
        final Label end = method.mark();
        method.catchException(start, end, THROWABLE);
        method.storeLocal(failure);
        method.loadArg(0);
        method.invokeVirtual(INPUT, new Method("close", "()V"));
        method.loadLocal(failure);
        method.throwException();
        method.endMethod();
    }

    private static void sha256(final ClassWriter writer) {
        final GeneratorAdapter method = new GeneratorAdapter(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC,
                new Method("sha256", "([B)Ljava/lang/String;"), null,
                new Type[]{Type.getType(java.security.NoSuchAlgorithmException.class)}, writer);
        final int digest = method.newLocal(Type.getType(byte[].class));
        final int encoded = method.newLocal(Type.getType(char[].class));
        final int index = method.newLocal(Type.INT_TYPE);
        final int value = method.newLocal(Type.INT_TYPE);
        method.push("SHA-256");
        method.invokeStatic(MESSAGE_DIGEST,
                new Method("getInstance", "(Ljava/lang/String;)Ljava/security/MessageDigest;"));
        method.loadArg(0);
        method.invokeVirtual(MESSAGE_DIGEST, new Method("digest", "([B)[B"));
        method.storeLocal(digest);
        method.loadLocal(digest);
        method.arrayLength();
        method.push(2);
        method.math(GeneratorAdapter.MUL, Type.INT_TYPE);
        method.newArray(Type.CHAR_TYPE);
        method.storeLocal(encoded);
        method.push(0);
        method.storeLocal(index);
        final Label loop = method.mark();
        method.loadLocal(index);
        method.loadLocal(digest);
        method.arrayLength();
        final Label done = method.newLabel();
        method.ifICmp(GeneratorAdapter.GE, done);
        method.loadLocal(digest);
        method.loadLocal(index);
        method.arrayLoad(Type.BYTE_TYPE);
        method.push(255);
        method.math(GeneratorAdapter.AND, Type.INT_TYPE);
        method.storeLocal(value);
        hexNibble(method, encoded, index, value, false);
        hexNibble(method, encoded, index, value, true);
        method.iinc(index, 1);
        method.goTo(loop);
        method.mark(done);
        method.newInstance(STRING);
        method.dup();
        method.loadLocal(encoded);
        method.invokeConstructor(STRING, new Method("<init>", "([C)V"));
        method.returnValue();
        method.endMethod();
    }

    private static void hexNibble(
            final GeneratorAdapter method,
            final int encoded,
            final int index,
            final int value,
            final boolean low
    ) {
        method.loadLocal(encoded);
        method.loadLocal(index);
        method.push(2);
        method.math(GeneratorAdapter.MUL, Type.INT_TYPE);
        if (low) {
            method.push(1);
            method.math(GeneratorAdapter.ADD, Type.INT_TYPE);
        }
        method.push("0123456789abcdef");
        method.loadLocal(value);
        method.push(low ? 15 : 4);
        method.math(low ? GeneratorAdapter.AND : GeneratorAdapter.USHR, Type.INT_TYPE);
        method.invokeVirtual(STRING, new Method("charAt", "(I)C"));
        method.arrayStore(Type.CHAR_TYPE);
    }

    /** Kept package-visible in bytecode so platform aliases can be tested without loading a library. */
    private static void normalizePlatform(final ClassWriter writer) {
        final GeneratorAdapter method = new GeneratorAdapter(
                Opcodes.ACC_STATIC,
                new Method("normalizePlatform", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;"),
                null, null, writer);
        method.loadArg(0);
        method.getStatic(LOCALE, "ROOT", LOCALE);
        method.invokeVirtual(STRING, new Method("toLowerCase", "(Ljava/util/Locale;)Ljava/lang/String;"));
        method.storeArg(0);
        method.loadArg(1);
        method.getStatic(LOCALE, "ROOT", LOCALE);
        method.invokeVirtual(STRING, new Method("toLowerCase", "(Ljava/util/Locale;)Ljava/lang/String;"));
        method.storeArg(1);
        final Label darwin = contains(method, 0, "darwin");
        final Label windows = contains(method, 0, "win");
        final Label macos = contains(method, 0, "mac");
        final Label linux = contains(method, 0, "linux");
        final Label unsupported = method.newLabel();
        method.goTo(unsupported);
        method.mark(windows);
        platformArch(method, "windows", unsupported);
        method.mark(macos);
        platformArch(method, "macos", unsupported);
        method.mark(darwin);
        platformArch(method, "macos", unsupported);
        method.mark(linux);
        platformArch(method, "linux", unsupported);
        method.mark(unsupported);
        method.visitInsn(Opcodes.ACONST_NULL);
        method.returnValue();
        method.endMethod();
    }

    private static Label contains(final GeneratorAdapter method, final int argument, final String value) {
        final Label found = method.newLabel();
        method.loadArg(argument);
        method.push(value);
        method.invokeVirtual(STRING, new Method("contains", "(Ljava/lang/CharSequence;)Z"));
        method.ifZCmp(GeneratorAdapter.NE, found);
        return found;
    }

    private static void platformArch(
            final GeneratorAdapter method,
            final String os,
            final Label unsupported
    ) {
        final Label x64 = method.newLabel();
        final Label arm64 = method.newLabel();
        for (final String alias : new String[]{"amd64", "x86_64", "x64", "x86-64"}) {
            method.loadArg(1);
            method.push(alias);
            method.invokeVirtual(STRING, new Method("equals", "(Ljava/lang/Object;)Z"));
            method.ifZCmp(GeneratorAdapter.NE, x64);
        }
        for (final String alias : new String[]{"aarch64", "arm64"}) {
            method.loadArg(1);
            method.push(alias);
            method.invokeVirtual(STRING, new Method("equals", "(Ljava/lang/Object;)Z"));
            method.ifZCmp(GeneratorAdapter.NE, arm64);
        }
        method.goTo(unsupported);
        method.mark(x64);
        method.push(os + "-x86_64");
        method.returnValue();
        method.mark(arm64);
        method.push(os + "-aarch64");
        method.returnValue();
    }

    private static void lookup(
            final ClassWriter writer,
            final Map<NativeTarget, NativeLoaderSpec.Library> libraries,
            final Lookup lookup
    ) {
        final GeneratorAdapter method = new GeneratorAdapter(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC,
                new Method(lookup.methodName, "(Ljava/lang/String;)Ljava/lang/String;"), null, null, writer);
        for (final NativeTarget target : NativeTarget.values()) {
            final NativeLoaderSpec.Library library = libraries.get(target);
            if (library == null) {
                continue;
            }
            method.loadArg(0);
            method.push(target.id());
            method.invokeVirtual(STRING, new Method("equals", "(Ljava/lang/Object;)Z"));
            final Label next = method.newLabel();
            method.ifZCmp(GeneratorAdapter.EQ, next);
            method.push(lookup.value(library));
            method.returnValue();
            method.mark(next);
        }
        method.visitInsn(Opcodes.ACONST_NULL);
        method.returnValue();
        method.endMethod();
    }

    private static void lookupSize(
            final ClassWriter writer,
            final Map<NativeTarget, NativeLoaderSpec.Library> libraries
    ) {
        final GeneratorAdapter method = new GeneratorAdapter(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC,
                new Method("sizeFor", "(Ljava/lang/String;)I"), null, null, writer);
        for (final NativeTarget target : NativeTarget.values()) {
            final NativeLoaderSpec.Library library = libraries.get(target);
            if (library == null) {
                continue;
            }
            method.loadArg(0);
            method.push(target.id());
            method.invokeVirtual(STRING, new Method("equals", "(Ljava/lang/Object;)Z"));
            final Label next = method.newLabel();
            method.ifZCmp(GeneratorAdapter.EQ, next);
            method.push(library.size());
            method.returnValue();
            method.mark(next);
        }
        method.push(-1);
        method.returnValue();
        method.endMethod();
    }

    private static void ensureLoaded(
            final ClassWriter writer,
            final Type owner,
            final NativeLoaderSpec spec
    ) {
        final GeneratorAdapter method = new GeneratorAdapter(
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_SYNCHRONIZED,
                new Method("ensureLoaded", "()V"), null, null, writer);
        method.getStatic(owner, "loaded", Type.BOOLEAN_TYPE);
        final Label load = method.newLabel();
        method.ifZCmp(GeneratorAdapter.EQ, load);
        method.returnValue();
        method.mark(load);
        final int targetId = method.newLocal(STRING);
        final int input = method.newLocal(INPUT);
        final int bytes = method.newLocal(Type.getType(byte[].class));
        final int resource = method.newLocal(STRING);
        final int digest = method.newLocal(STRING);
        final int fileName = method.newLocal(STRING);
        final int expectedSize = method.newLocal(Type.INT_TYPE);
        final int directory = method.newLocal(FILE);
        final int target = method.newLocal(FILE);
        final int temporary = method.newLocal(FILE);
        final int output = method.newLocal(FILE_OUTPUT);
        final int failure = method.newLocal(THROWABLE);
        final Label protectedStart = method.mark();

        method.push("os.name");
        method.push("");
        method.invokeStatic(SYSTEM, new Method("getProperty", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;"));
        method.push("os.arch");
        method.push("");
        method.invokeStatic(SYSTEM, new Method("getProperty", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;"));
        method.invokeStatic(owner, new Method("normalizePlatform",
                "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;"));
        method.storeLocal(targetId);
        method.loadLocal(targetId);
        final Label platformKnown = method.newLabel();
        method.ifNonNull(platformKnown);
        throwLinkError(method, "Unsupported operating system or architecture");
        method.mark(platformKnown);

        readResource(method, owner, spec.manifestResourcePath(), spec.manifestSize(), input, bytes,
                "Embedded native manifest is missing");
        digestCheck(method, owner, bytes, spec.manifestSha256(),
                "Embedded native manifest digest mismatch");

        method.loadLocal(targetId);
        method.invokeStatic(owner, new Method("resourceFor", "(Ljava/lang/String;)Ljava/lang/String;"));
        method.storeLocal(resource);
        method.loadLocal(resource);
        final Label artifactAvailable = method.newLabel();
        method.ifNonNull(artifactAvailable);
        throwLinkError(method, "No embedded native library supports this platform");
        method.mark(artifactAvailable);
        method.loadLocal(targetId);
        method.invokeStatic(owner, new Method("digestFor", "(Ljava/lang/String;)Ljava/lang/String;"));
        method.storeLocal(digest);
        method.loadLocal(targetId);
        method.invokeStatic(owner, new Method("fileNameFor", "(Ljava/lang/String;)Ljava/lang/String;"));
        method.storeLocal(fileName);
        method.loadLocal(targetId);
        method.invokeStatic(owner, new Method("sizeFor", "(Ljava/lang/String;)I"));
        method.storeLocal(expectedSize);

        method.push(owner);
        method.loadLocal(resource);
        prefixSlash(method);
        method.invokeVirtual(CLASS,
                new Method("getResourceAsStream", "(Ljava/lang/String;)Ljava/io/InputStream;"));
        method.storeLocal(input);
        method.loadLocal(input);
        final Label libraryPresent = method.newLabel();
        method.ifNonNull(libraryPresent);
        throwLinkError(method, "Embedded native library is missing");
        method.mark(libraryPresent);
        method.loadLocal(input);
        method.loadLocal(expectedSize);
        method.invokeStatic(owner, new Method("readFully", "(Ljava/io/InputStream;I)[B"));
        method.storeLocal(bytes);
        digestCheckLocal(method, owner, bytes, digest, "Embedded native library digest mismatch");

        extractionDirectory(method, spec.buildId(), spec.manifestSha256(), directory);
        method.newInstance(FILE);
        method.dup();
        method.loadLocal(directory);
        method.loadLocal(fileName);
        method.invokeConstructor(FILE, new Method("<init>", "(Ljava/io/File;Ljava/lang/String;)V"));
        method.invokeVirtual(FILE, new Method("getAbsoluteFile", "()Ljava/io/File;"));
        method.storeLocal(target);
        rejectSymbolicLink(method, target, "Native library extraction target is a symbolic link");
        final Label write = method.newLabel();
        final Label ready = method.newLabel();
        method.loadLocal(target);
        method.invokeVirtual(FILE, new Method("isFile", "()Z"));
        method.ifZCmp(GeneratorAdapter.EQ, write);
        method.loadLocal(target);
        method.invokeVirtual(FILE, new Method("length", "()J"));
        method.loadLocal(expectedSize);
        method.cast(Type.INT_TYPE, Type.LONG_TYPE);
        method.ifCmp(Type.LONG_TYPE, GeneratorAdapter.NE, write);
        method.loadLocal(target);
        method.invokeVirtual(FILE, new Method("toPath", "()Ljava/nio/file/Path;"));
        method.invokeStatic(FILES, new Method("readAllBytes", "(Ljava/nio/file/Path;)[B"));
        method.invokeStatic(owner, new Method("sha256", "([B)Ljava/lang/String;"));
        method.loadLocal(digest);
        method.invokeVirtual(STRING, new Method("equals", "(Ljava/lang/Object;)Z"));
        method.ifZCmp(GeneratorAdapter.NE, ready);
        method.mark(write);
        method.push("skid-");
        method.push(".tmp");
        method.loadLocal(directory);
        method.invokeStatic(FILE,
                new Method("createTempFile", "(Ljava/lang/String;Ljava/lang/String;Ljava/io/File;)Ljava/io/File;"));
        method.storeLocal(temporary);
        method.newInstance(FILE_OUTPUT);
        method.dup();
        method.loadLocal(temporary);
        method.invokeConstructor(FILE_OUTPUT, new Method("<init>", "(Ljava/io/File;)V"));
        method.storeLocal(output);
        method.loadLocal(output);
        method.loadLocal(bytes);
        method.invokeVirtual(FILE_OUTPUT, new Method("write", "([B)V"));
        method.loadLocal(output);
        method.invokeVirtual(FILE_OUTPUT, new Method("getFD", "()Ljava/io/FileDescriptor;"));
        method.invokeVirtual(FILE_DESCRIPTOR, new Method("sync", "()V"));
        method.loadLocal(output);
        method.invokeVirtual(FILE_OUTPUT, new Method("close", "()V"));
        atomicMove(method, temporary, target);
        method.loadLocal(temporary);
        method.invokeVirtual(FILE, new Method("delete", "()Z"));
        method.pop();
        method.mark(ready);
        permissions(method, target, true);
        method.loadLocal(target);
        method.invokeVirtual(FILE, new Method("getAbsolutePath", "()Ljava/lang/String;"));
        method.invokeStatic(SYSTEM, new Method("load", "(Ljava/lang/String;)V"));
        method.push(true);
        method.putStatic(owner, "loaded", Type.BOOLEAN_TYPE);
        method.returnValue();
        final Label protectedEnd = method.mark();
        method.catchException(protectedStart, protectedEnd, THROWABLE);
        method.storeLocal(failure);
        method.newInstance(LINK_ERROR);
        method.dup();
        method.push("Failed to load protected native library");
        method.invokeConstructor(LINK_ERROR, new Method("<init>", "(Ljava/lang/String;)V"));
        method.dup();
        method.loadLocal(failure);
        method.invokeVirtual(THROWABLE,
                new Method("initCause", "(Ljava/lang/Throwable;)Ljava/lang/Throwable;"));
        method.pop();
        method.throwException();
        method.endMethod();
    }

    private static void readResource(
            final GeneratorAdapter method,
            final Type owner,
            final String path,
            final int expectedSize,
            final int input,
            final int bytes,
            final String missingMessage
    ) {
        method.push(owner);
        method.push("/" + path);
        method.invokeVirtual(CLASS,
                new Method("getResourceAsStream", "(Ljava/lang/String;)Ljava/io/InputStream;"));
        method.storeLocal(input);
        method.loadLocal(input);
        final Label present = method.newLabel();
        method.ifNonNull(present);
        throwLinkError(method, missingMessage);
        method.mark(present);
        method.loadLocal(input);
        method.push(expectedSize);
        method.invokeStatic(owner, new Method("readFully", "(Ljava/io/InputStream;I)[B"));
        method.storeLocal(bytes);
    }

    private static void prefixSlash(final GeneratorAdapter method) {
        method.newInstance(Type.getType(StringBuilder.class));
        method.dup();
        method.invokeConstructor(Type.getType(StringBuilder.class), new Method("<init>", "()V"));
        method.push("/");
        method.invokeVirtual(Type.getType(StringBuilder.class),
                new Method("append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;"));
        method.swap();
        method.invokeVirtual(Type.getType(StringBuilder.class),
                new Method("append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;"));
        method.invokeVirtual(Type.getType(StringBuilder.class), new Method("toString", "()Ljava/lang/String;"));
    }

    private static void digestCheck(
            final GeneratorAdapter method, final Type owner, final int bytes,
            final String expected, final String message
    ) {
        method.loadLocal(bytes);
        method.invokeStatic(owner, new Method("sha256", "([B)Ljava/lang/String;"));
        method.push(expected);
        digestComparison(method, message);
    }

    private static void digestCheckLocal(
            final GeneratorAdapter method, final Type owner, final int bytes,
            final int expected, final String message
    ) {
        method.loadLocal(bytes);
        method.invokeStatic(owner, new Method("sha256", "([B)Ljava/lang/String;"));
        method.loadLocal(expected);
        digestComparison(method, message);
    }

    private static void digestComparison(final GeneratorAdapter method, final String message) {
        method.invokeVirtual(STRING, new Method("equals", "(Ljava/lang/Object;)Z"));
        final Label valid = method.newLabel();
        method.ifZCmp(GeneratorAdapter.NE, valid);
        throwLinkError(method, message);
        method.mark(valid);
    }

    private static void extractionDirectory(
            final GeneratorAdapter method,
            final String buildId,
            final String manifestDigest,
            final int directory
    ) {
        /* Files.createTempDirectory is collision-safe across class loaders. An identity hash is
         * not a unique class-loader identity and could make the JVM reject the same library path
         * as already loaded by another loader. */
        method.push("skidfuscator-" + buildId + "-" + manifestDigest.substring(0, 12) + "-");
        method.push(0);
        method.newArray(FILE_ATTRIBUTE);
        method.invokeStatic(FILES, new Method("createTempDirectory",
                "(Ljava/lang/String;[Ljava/nio/file/attribute/FileAttribute;)Ljava/nio/file/Path;"));
        method.invokeInterface(PATH, new Method("toFile", "()Ljava/io/File;"));
        method.invokeVirtual(FILE, new Method("getAbsoluteFile", "()Ljava/io/File;"));
        method.storeLocal(directory);
        rejectSymbolicLink(method, directory, "Native extraction directory is a symbolic link");
        permissions(method, directory, false);
    }

    private static void permissions(final GeneratorAdapter method, final int file, final boolean executable) {
        method.loadLocal(file);
        method.push(true);
        method.push(true);
        method.invokeVirtual(FILE, new Method("setReadable", "(ZZ)Z"));
        method.pop();
        method.loadLocal(file);
        method.push(!executable);
        method.push(true);
        method.invokeVirtual(FILE, new Method("setWritable", "(ZZ)Z"));
        method.pop();
        method.loadLocal(file);
        method.push(true);
        method.push(true);
        method.invokeVirtual(FILE, new Method("setExecutable", "(ZZ)Z"));
        method.pop();
    }

    private static void atomicMove(final GeneratorAdapter method, final int temporary, final int target) {
        move(method, temporary, target, true);
    }

    private static void rejectSymbolicLink(
            final GeneratorAdapter method,
            final int file,
            final String message
    ) {
        method.loadLocal(file);
        method.invokeVirtual(FILE, new Method("toPath", "()Ljava/nio/file/Path;"));
        method.invokeStatic(FILES, new Method("isSymbolicLink", "(Ljava/nio/file/Path;)Z"));
        final Label safe = method.newLabel();
        method.ifZCmp(GeneratorAdapter.EQ, safe);
        method.newInstance(IO_EXCEPTION);
        method.dup();
        method.push(message);
        method.invokeConstructor(IO_EXCEPTION, new Method("<init>", "(Ljava/lang/String;)V"));
        method.throwException();
        method.mark(safe);
    }

    private static void move(
            final GeneratorAdapter method,
            final int temporary,
            final int target,
            final boolean atomic
    ) {
        method.loadLocal(temporary);
        method.invokeVirtual(FILE, new Method("toPath", "()Ljava/nio/file/Path;"));
        method.loadLocal(target);
        method.invokeVirtual(FILE, new Method("toPath", "()Ljava/nio/file/Path;"));
        method.push(atomic ? 2 : 1);
        method.newArray(COPY_OPTION);
        method.dup();
        method.push(0);
        method.getStatic(STANDARD_COPY_OPTION, "REPLACE_EXISTING", STANDARD_COPY_OPTION);
        method.arrayStore(COPY_OPTION);
        if (atomic) {
            method.dup();
            method.push(1);
            method.getStatic(STANDARD_COPY_OPTION, "ATOMIC_MOVE", STANDARD_COPY_OPTION);
            method.arrayStore(COPY_OPTION);
        }
        method.invokeStatic(FILES, new Method("move",
                "(Ljava/nio/file/Path;Ljava/nio/file/Path;[Ljava/nio/file/CopyOption;)Ljava/nio/file/Path;"));
        method.pop();
    }

    private static void throwLinkError(final GeneratorAdapter method, final String message) {
        method.newInstance(LINK_ERROR);
        method.dup();
        method.push(message);
        method.invokeConstructor(LINK_ERROR, new Method("<init>", "(Ljava/lang/String;)V"));
        method.throwException();
    }

    private enum Lookup {
        RESOURCE("resourceFor") {
            @Override String value(final NativeLoaderSpec.Library library) { return library.resourcePath(); }
        },
        DIGEST("digestFor") {
            @Override String value(final NativeLoaderSpec.Library library) { return library.sha256(); }
        },
        FILE_NAME("fileNameFor") {
            @Override String value(final NativeLoaderSpec.Library library) { return library.fileName(); }
        };

        private final String methodName;

        Lookup(final String methodName) {
            this.methodName = methodName;
        }

        abstract String value(NativeLoaderSpec.Library library);
    }

    public record GeneratedLoader(String internalName, byte[] bytecode) {
        public GeneratedLoader {
            Objects.requireNonNull(internalName, "internalName");
            bytecode = Objects.requireNonNull(bytecode, "bytecode").clone();
        }

        @Override
        public byte[] bytecode() {
            return bytecode.clone();
        }
    }
}
