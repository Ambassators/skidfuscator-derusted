package dev.skidfuscator.obfuscator.creator;

import dev.skidfuscator.obfuscator.Skidfuscator;
import dev.skidfuscator.obfuscator.creator.pass.SkidLocalsReallocator;
import dev.skidfuscator.obfuscator.skidasm.cfg.SkidBlockFactory;
import org.mapleir.asm.MethodNode;
import org.mapleir.ir.algorithms.BoissinotDestructor;
import org.mapleir.ir.algorithms.LocalsReallocator;
import org.mapleir.ir.cfg.ControlFlowGraph;
import org.mapleir.ir.cfg.SSAFactory;
import org.mapleir.ir.cfg.builder.*;

public class SkidFlowGraphBuilder extends ControlFlowGraphBuilder {
    private final Skidfuscator skidfuscator;

    public SkidFlowGraphBuilder(MethodNode method, Skidfuscator skidfuscator) {
        super(method);
        this.skidfuscator = skidfuscator;
    }

    public SkidFlowGraphBuilder(MethodNode method, SSAFactory factory, Skidfuscator skidfuscator) {
        super(method, factory);
        this.skidfuscator = skidfuscator;
    }

    public SkidFlowGraphBuilder(MethodNode method, SSAFactory factory, boolean optimise, Skidfuscator skidfuscator) {
        super(method, factory, optimise);
        this.skidfuscator = skidfuscator;
    }

    @Override
    protected BuilderPass[] resolvePasses() {
        return new BuilderPass[] {
                new SkidGenerationPass(this, skidfuscator),
                new DeadBlocksPass(this),
                //new LocalFixerPass(this),
                //new NaturalisationPass(this),
                new SSAGenPass(this, true)
                //new CreationFixer(this)
        };
    }

    /** Rebuild finalized bytecode for native lowering without destroying SSA or allocating JVM locals. */
    public static ControlFlowGraph buildNativeSsa(final Skidfuscator skidfuscator, final MethodNode method) {
        return new SkidFlowGraphBuilder(method, SkidBlockFactory.v(skidfuscator), skidfuscator).buildImpl();
    }

    public static ControlFlowGraph build(final Skidfuscator skidfuscator, final MethodNode method) {
        ControlFlowGraphBuilder builder = new SkidFlowGraphBuilder(method, SkidBlockFactory.v(skidfuscator), skidfuscator);
        final ControlFlowGraph cfg = builder.buildImpl();
        snapshot(method, cfg, "ssa");
        BoissinotDestructor.leaveSSA(cfg);
        snapshot(method, cfg, "lowered");
        try {
            SkidLocalsReallocator.realloc(skidfuscator, cfg);
            snapshot(method, cfg, "allocated");
        } catch (RuntimeException e) {
            throw new IllegalStateException("Local allocation failed for " + method.getOwner() + "#"
                    + method.getName() + method.getDesc(), e);
        }

        return cfg;
    }

    /** Explicit, local-only diagnostics for locating SSA/allocation regressions. */
    private static void snapshot(MethodNode method, ControlFlowGraph graph, String phase) {
        String prefixes = System.getProperty("skid.debug.graphPrefix", "");
        String directory = System.getProperty("skid.debug.graphDirectory", "");
        if (prefixes.isEmpty() || directory.isEmpty()) return;
        boolean selected = java.util.Arrays.stream(prefixes.split(","))
                .map(String::trim).filter(prefix -> !prefix.isEmpty())
                .anyMatch(prefix -> method.getOwner().startsWith(prefix));
        if (!selected) return;
        String name = (method.getOwner() + "_" + method.getName())
                .replaceAll("[^A-Za-z0-9_$.-]", "_")
                + "_" + Integer.toHexString(method.getDesc().hashCode()) + ".txt";
        try {
            java.nio.file.Path target = java.nio.file.Paths.get(directory, phase);
            java.nio.file.Files.createDirectories(target);
            java.nio.file.Files.writeString(target.resolve(name), graph.toString(),
                    java.nio.charset.StandardCharsets.UTF_8);
        } catch (java.io.IOException failure) {
            throw new IllegalStateException("Cannot write requested graph diagnostic for "
                    + method.getOwner() + "#" + method.getName(), failure);
        }
    }
}
