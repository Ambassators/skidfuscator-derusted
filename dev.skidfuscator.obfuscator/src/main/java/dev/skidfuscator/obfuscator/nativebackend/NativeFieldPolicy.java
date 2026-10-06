package dev.skidfuscator.obfuscator.nativebackend;

import dev.skidfuscator.config.nativeobfuscation.NativeConfig;
import dev.skidfuscator.nativeir.*;
import dev.skidfuscator.obfuscator.nativebackend.commit.NativeMethodCommitTransaction;
import org.mapleir.asm.ClassNode;
import org.mapleir.asm.MethodNode;
import org.objectweb.asm.*;
import org.objectweb.asm.commons.Remapper;
import org.objectweb.asm.tree.*;

import java.io.IOException;
import java.nio.file.*;
import java.util.*;
import java.util.function.*;
import java.util.regex.Pattern;

/** Moves only successfully lowered, reviewed primitive state with no surviving JVM field boundary. */
final class NativeFieldPolicy {
    record Field(ClassNode owner, org.objectweb.asm.tree.FieldNode node, String finalOwner,
                 String finalName, String finalDescriptor, int slot) {
        String key() { return finalOwner + "#" + finalName + ":" + finalDescriptor; }
    }
    record Row(Field field, String status, Set<String> reasons) { }
    record Result(List<Field> removed, List<Row> rows) {
        NativeFunction rewrite(NativeFunction source) {
            if (removed.isEmpty()) return source;
            Map<String,Field> fields=new HashMap<>(); removed.forEach(f -> fields.put(f.key(),f));
            NativeFunction copy=new NativeFunction(source.symbol(),source.javaOwner(),source.javaName(),
                    source.javaDescriptor(),source.returnType(),source.parameters(),source.entryBlock(),
                    source.backend(),source.synchronizedMethod(),source.requiresSemanticContext(),source.metadata());
            for(NativeBlock block:source.blocks()) {
                NativeBlock next=new NativeBlock(block.id());
                for(NativeInstruction insn:block.instructions()) {
                    if(insn instanceof NativeInstruction.Operation op && fieldOperation(op)) {
                        Field f=fields.get(operationKey(op));
                        if(f!=null) {
                            Map<String,String> attributes=new HashMap<>(op.attributes());
                            attributes.put("native.field.storage","primitive-weak-identity-v1");
                            attributes.put("native.field.slot",Integer.toString(f.slot()));
                            attributes.put("native.field.proof","closed-world-v1");
                            attributes.put("native.field.volatile",Boolean.toString((f.node().access&Opcodes.ACC_VOLATILE)!=0));
                            insn=new NativeInstruction.Operation(op.id(),op.type(),op.opcode(),op.operands(),attributes,op.sourceLocation());
                        }
                    }
                    next.addInstruction(insn);
                }
                block.exceptionEdges().forEach(next::addExceptionEdge);
                next.terminate(block.terminator().orElseThrow()); copy.addBlock(next);
            }
            return copy;
        }
        void report(String configured) throws IOException {
            if(configured.isBlank()) return;
            List<String> lines=new ArrayList<>(List.of("status\towner\tfield\tdescriptor\tfinalOwner\tfinalField\tfinalDescriptor\tslot\treasons\tannotations"));
            for(Row row:rows) {
                Field f=row.field(); Set<String> annotations=new TreeSet<>();
                annotationNames(f.node().visibleAnnotations,annotations);annotationNames(f.node().invisibleAnnotations,annotations);
                annotationNames(f.node().visibleTypeAnnotations,annotations);annotationNames(f.node().invisibleTypeAnnotations,annotations);
                annotationNames(f.owner().node.visibleAnnotations,annotations);annotationNames(f.owner().node.invisibleAnnotations,annotations);
                lines.add(row.status()+"\t"+f.owner().getName()+"\t"+f.node().name+"\t"+f.node().desc+"\t"+f.finalOwner()+"\t"+f.finalName()+"\t"+f.finalDescriptor()+"\t"+f.slot()+"\t"+String.join(" | ",new TreeSet<>(row.reasons()))+"\t"+String.join(" | ",annotations));
            }
            Path path=Path.of(configured).toAbsolutePath();Files.createDirectories(path.getParent());Files.write(path,lines);
        }
    }
    static Result plan(NativeConfig config, List<NativeEntryPolicy.Body> bodies, Collection<ClassNode> owners,
                       Collection<MethodNode> methods, Collection<JavaLinkageHelper> helpers,
                       Predicate<org.objectweb.asm.tree.FieldNode> contract,
                       Function<String,ClassNode> resolver, Remapper remapper, List<String> exportedPackages) {
        if(!config.isNativeFieldStorageEnabled()) return new Result(List.of(),List.of());
        if(config.getNativeFieldIncludes().isEmpty()) throw new IllegalArgumentException("native.fields.include must define a reviewed class scope");
        List<Pattern> include=config.getNativeFieldIncludes().stream().map(Pattern::compile).toList();
        Map<String,Field> fields=new TreeMap<>();int slot=0;
        for(ClassNode owner:owners.stream().sorted(Comparator.comparing(ClassNode::getName)).toList()) {
            if(include.stream().noneMatch(p->p.matcher(owner.getName()).matches())) continue;
            for(var node:owner.node.fields) {
                Field f=new Field(owner,node,remapper.mapType(owner.getName()),remapper.mapFieldName(owner.getName(),node.name,node.desc),remapper.mapDesc(node.desc),slot++);
                fields.put(f.key(),f);
            }
        }
        Map<String,Set<String>> reasons=new HashMap<>(); fields.keySet().forEach(k->reasons.put(k,new TreeSet<>()));
        // A subclass can expose inherited state to serialization/cloning/layout readers.
        // Its boundary also protects fields declared on an otherwise ordinary superclass.
        Set<String> inheritedLayouts=new HashSet<>();
        for(ClassNode owner:owners) {
            boolean layout=annotated(owner.node.visibleAnnotations)||annotated(owner.node.invisibleAnnotations);
            for(String base:List.of("java/io/Serializable","java/lang/Cloneable","com/sun/jna/Structure","com/google/protobuf/GeneratedMessageLite","com/google/protobuf/GeneratedMessageV3","com/google/protobuf/GeneratedMessage"))
                layout|=inherits(owner,base,resolver,new HashSet<>());
            if(layout) collectAncestors(owner,resolver,inheritedLayouts,new HashSet<>());
        }
        Map<MethodNode,NativeEntryPolicy.Body> converted=new IdentityHashMap<>(); bodies.forEach(b->converted.put(b.method(),b));
        Set<String> literals=new HashSet<>(),handles=new HashSet<>(),javaRefs=new HashSet<>(),nativeRefs=new HashSet<>();
        for(MethodNode method:methods) {
            var body=converted.get(method);
            scan(method.node,body==null||body.copy(),literals,handles,javaRefs);
            if(body!=null&&body.mutation() instanceof NativeMethodCommitTransaction.Wrapper w)scan(w.wrapperTemplate(),true,literals,handles,javaRefs);
        }
        helpers.forEach(h->scan(h.method(),true,literals,handles,javaRefs));
        // Resolve inherited field aliases in surviving Java exactly as the JVM does.
        for(String ref:List.copyOf(javaRefs))resolve(ref,resolver,new HashSet<>()).ifPresent(javaRefs::add);
        for(String ref:List.copyOf(handles))resolve(ref,resolver,new HashSet<>()).ifPresent(handles::add);
        for(var body:bodies)for(NativeBlock block:body.function().blocks())for(NativeInstruction insn:block.instructions()) {
            if(!(insn instanceof NativeInstruction.Operation op)||!fieldOperation(op))continue;
            String key=operationKey(op);Field f=fields.get(key);
            if(f==null) {
                // An inherited or renamed symbolic owner needs the existing JVM field lookup.
                for(Field candidate:fields.values())if(candidate.finalName().equals(op.attributes().get("name"))&&candidate.finalDescriptor().equals(op.attributes().get("descriptor")))
                    reasons.get(candidate.key()).add("unresolved/inherited native field owner");
                continue;
            }
            nativeRefs.add(key);
            if(body.function().backend()!=NativeBackend.AOT)reasons.get(key).add("VM field access requires Java storage");
            if(!Boolean.toString((f.node().access&Opcodes.ACC_STATIC)!=0).equals(op.attributes().get("static")))reasons.get(key).add("native field static shape mismatch");
        }
        List<Field> removed=new ArrayList<>();List<Row> rows=new ArrayList<>();
        for(Field f:fields.values()) {
            Set<String> rs=reasons.get(f.key());var n=f.node();String original=f.owner().getName()+"#"+n.name+":"+n.desc;
            if(n.desc.length()!=1||"ZBCSIJFD".indexOf(n.desc.charAt(0))<0)rs.add("reference/array storage requires JVM garbage collection");
            if((n.access&(Opcodes.ACC_FINAL|Opcodes.ACC_ENUM))!=0||n.value!=null)rs.add("final/constant/enum field");
            if(annotated(n.visibleAnnotations)||annotated(n.invisibleAnnotations)||annotated(n.visibleTypeAnnotations)||annotated(n.invisibleTypeAnnotations))rs.add("field annotation or type annotation");
            if(annotated(f.owner().node.visibleAnnotations)||annotated(f.owner().node.invisibleAnnotations))rs.add("class annotation may expose field layout");
            if(inheritedLayouts.contains(f.owner().getName()))rs.add("subclass/owner exposes inherited field layout");
            for(String base:List.of("java/io/Serializable","java/lang/Cloneable","com/sun/jna/Structure","com/sun/jna/Library","com/google/protobuf/GeneratedMessageLite","com/google/protobuf/GeneratedMessageV3","com/google/protobuf/GeneratedMessage"))
                if(inherits(f.owner(),base,resolver,new HashSet<>()))rs.add("runtime field-layout contract: "+base);
            if(exportedPackages.stream().anyMatch(p->f.owner().getName().startsWith(p)))rs.add("exported API field");
            if(contract.test(n))rs.add("recorded reflection/native/Java compatibility contract");
            if(config.getNativeFieldKeeps().contains(original)||config.getNativeFieldKeeps().contains(f.key()))rs.add("configured field keep");
            if(javaRefs.contains(original)||javaRefs.contains(f.key()))rs.add("surviving Java field access (including constructors/initializers/wrappers)");
            if(handles.contains(original)||handles.contains(f.key()))rs.add("field handle or dynamic linkage");
            if(literals.contains(n.name)||literals.contains(f.finalName()))rs.add("conservative reflection field-name literal in reader/caller class");
            if(n.name.equals("serialVersionUID")||n.name.equals("serialPersistentFields"))rs.add("Java serialization metadata");
            if(!nativeRefs.contains(f.key()))rs.add("no committed native field access");
            if(rs.isEmpty())removed.add(f);
            rows.add(new Row(f,rs.isEmpty()?"NATIVE_STORAGE":"JAVA_FIELD",Set.copyOf(rs)));
        }
        return new Result(List.copyOf(removed),List.copyOf(rows));
    }
    static boolean fieldOperation(NativeInstruction.Operation op){return op.opcode()==NativeOpcode.FIELD_GET||op.opcode()==NativeOpcode.FIELD_SET;}
    static String operationKey(NativeInstruction.Operation op){return op.attributes().get("owner")+"#"+op.attributes().get("name")+":"+op.attributes().get("descriptor");}
    private static boolean annotated(List<? extends AnnotationNode> list){return list!=null&&!list.isEmpty();}
    private static void annotationNames(List<? extends AnnotationNode> list,Set<String> result){if(list!=null)list.forEach(a->result.add(Type.getType(a.desc).getClassName()));}
    private static boolean inherits(ClassNode owner,String target,Function<String,ClassNode> resolver,Set<String> seen){
        if(owner==null)return true; // unresolved ancestry cannot prove a closed field layout
        if(!seen.add(owner.getName()))return false;if(owner.getName().equals(target))return true;
        if(owner.node.superName!=null&&inherits(resolver.apply(owner.node.superName),target,resolver,seen))return true;
        for(String i:owner.node.interfaces)if(inherits(resolver.apply(i),target,resolver,seen))return true;return false;
    }
    private static void collectAncestors(ClassNode owner,Function<String,ClassNode> resolver,Set<String> result,Set<String> seen){
        if(owner==null||!seen.add(owner.getName()))return;result.add(owner.getName());
        if(owner.node.superName!=null)collectAncestors(resolver.apply(owner.node.superName),resolver,result,seen);
        for(String i:owner.node.interfaces)collectAncestors(resolver.apply(i),resolver,result,seen);
    }
    private static Optional<String> resolve(String key,Function<String,ClassNode> resolver,Set<String> seen){
        int split=key.indexOf('#'),colon=key.indexOf(':',split);if(split<0||colon<0)return Optional.empty();
        String owner=key.substring(0,split),name=key.substring(split+1,colon),desc=key.substring(colon+1);
        if(!seen.add(owner))return Optional.empty();ClassNode node=resolver.apply(owner);if(node==null)return Optional.empty();
        if(node.node.fields.stream().anyMatch(f->f.name.equals(name)&&f.desc.equals(desc)))return Optional.of(key);
        for(String i:node.node.interfaces){var r=resolve(i+"#"+name+":"+desc,resolver,seen);if(r.isPresent())return r;}
        return node.node.superName==null?Optional.empty():resolve(node.node.superName+"#"+name+":"+desc,resolver,seen);
    }
    private static void scan(org.objectweb.asm.tree.MethodNode method,boolean code,Set<String> literals,Set<String> handles,Set<String> refs){
        Set<String> methodLiterals=new HashSet<>();boolean reflection=false;
        for(AbstractInsnNode insn:method.instructions){
            if(code&&insn instanceof FieldInsnNode f)refs.add(f.owner+"#"+f.name+":"+f.desc);
            if(insn instanceof MethodInsnNode c) {
                if(c.owner.equals("java/lang/Class")&&Set.of("getField","getDeclaredField","getFields","getDeclaredFields").contains(c.name))reflection=true;
                if(c.owner.equals("java/lang/invoke/MethodHandles$Lookup")&&Set.of("findGetter","findSetter","findStaticGetter","findStaticSetter","findVarHandle","findStaticVarHandle").contains(c.name))reflection=true;
            }
            if(insn instanceof LdcInsnNode l)constant(l.cst,methodLiterals,handles);
            if(insn instanceof InvokeDynamicInsnNode i){constant(i.bsm,methodLiterals,handles);for(Object arg:i.bsmArgs)constant(arg,methodLiterals,handles);}
        }
        if(reflection)literals.addAll(methodLiterals);
    }
    private static void constant(Object value,Set<String> literals,Set<String> handles){
        if(value instanceof String s)literals.add(s);
        else if(value instanceof Handle h&&h.getTag()<=Opcodes.H_PUTSTATIC)handles.add(h.getOwner()+"#"+h.getName()+":"+h.getDesc());
        else if(value instanceof ConstantDynamic d){constant(d.getBootstrapMethod(),literals,handles);for(int i=0;i<d.getBootstrapMethodArgumentCount();i++)constant(d.getBootstrapMethodArgument(i),literals,handles);}
    }
}
