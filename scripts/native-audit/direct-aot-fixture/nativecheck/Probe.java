package nativecheck;
import java.lang.reflect.Modifier;
import java.util.concurrent.atomic.AtomicInteger;

public class Probe {
    private static int passed,failed;
    interface Check { void run() throws Exception; }
    static void check(boolean value) { if(!value) throw new AssertionError(); }
    static void test(String name,Check check) {
        try { check.run(); passed++; System.out.println("PASS "+name); }
        catch(Throwable error) { failed++;System.out.println("FAIL "+name+" "+error);error.printStackTrace(); }
    }
    public static void main(String[] args) throws Exception {
        test("native-coverage",()-> {
            String[] required={"leaf","chain","loop","recursive","branch","slope","get","privateGet","privateChain","instanceChain","nullable","division","catchDivision","sum","objects","referenceIdentity","virtualCall","crossClass","shifts","charArray","shortArray","booleanArray","floatingArrays","nestedArray","nullArray","nullField","instanceOf","byteLoop","caughtIdentity","initializationCycle"};
            for(String name:required) { boolean found=false;for(java.lang.reflect.Method m:Targets.class.getDeclaredMethods())if(m.getName().equals(name)){found=true;check(Modifier.isNative(m.getModifiers()));}check(found); }
        });
        test("direct-pure-chain",()-> {for(int i=-1000;i<1000;i++)check(Targets.chain(i)==(i*3+7)+((i+1)*3+7));});
        test("lazy-class-initialization",()->check(InitTracker.initialized==0));
        test("loop-phi-direct",()-> {for(int n=0;n<200;n++){int expected=0;for(int i=0;i<n;i++)expected+=i*3+7;check(Targets.loop(n)==expected);}});
        test("recursive-direct",()->check(Targets.recursive(10)==3628800L));
        test("boolean-phi",()-> {check(Targets.branch(false,false)==0);check(Targets.branch(true,false)==1);check(Targets.branch(true,true)==2);});
        test("float-phi",()-> {check(Targets.slope(0,0,2,6)==3);check(Targets.slope(1,1,1,5)==0);});
        test("instance-final",()-> {Object a=new Object();check(Targets.instanceChain(new Targets(a))==a);});
        test("instance-private",()-> {Object a=new Object();check(new Targets(a).privateChain()==a);});
        test("null-exception-direct",()->check("null-caught".equals(Targets.nullable(null))));
        test("exception-through-direct",()-> {check(Targets.catchDivision(7,0)==-77);check(Targets.catchDivision(7,2)==3);check(Targets.division(Integer.MIN_VALUE,-1)==Integer.MIN_VALUE);});
        test("array-loop",()->check(Targets.sum(new int[]{1,-7,11,91})==96));
        test("object-array",()-> {Object a=new Object();Object[] result=Targets.objects(a);check(result.length==2 && result[0]==a && result[1]==a);});
        test("reference-handle-identity",()-> {Object a=new Object();check(Targets.referenceIdentity(new Targets(a),new Targets(a)));check(!Targets.referenceIdentity(new Targets(new Object()),new Targets(new Object())));});
        test("virtual-override-preserved",()-> {check(Targets.virtualCall(new Targets.Base())==4);check(Targets.virtualCall(new Targets.Derived())==9);});
        test("cross-class-direct",()-> {check(Targets.crossClass(7)==20);check(InitTracker.initialized==1);});
        test("masked-long-shifts",()-> {java.util.Random r=new java.util.Random(28);for(int i=0;i<3000;i++){long x=r.nextLong();int n=r.nextInt();check(Targets.shifts(x,n)==((x<<n)^(x>>>n)^(x>>n)));}});
        test("char-short-boolean-arrays",()-> {for(int i=0;i<65536;i+=41){check(Targets.charArray((char)i)==i);check(Targets.shortArray((short)i)==(short)i);}check(Targets.booleanArray(true));check(!Targets.booleanArray(false));});
        test("floating-point-arrays",()->check(Targets.floatingArrays(1.25f,2.75)==4));
        test("nested-primitive-array",()->check(Targets.nestedArray()==71));
        test("null-array-and-field",()-> {check(Targets.nullArray(null)==-9);check("field-null".equals(Targets.nullField(null)));});
        test("null-instanceof",()-> {check(!Targets.instanceOf(null));check(!Targets.instanceOf(new Object()));check(Targets.instanceOf(new Targets(null)));});
        test("byte-parameter-promotion",()-> {check(Targets.byteLoop((byte)10)==45);check(Targets.byteLoop((byte)-7)==0);});
        test("exception-identity-across-call",()-> {Throwable t=new IllegalArgumentException("sentinel");check(Targets.caughtIdentity(t)==t);});
        test("cyclic-class-initialization",()->check(Targets.initializationCycle()==21));
        test("concurrent-direct",()-> {AtomicInteger errors=new AtomicInteger();Thread[] ts=new Thread[4];for(int i=0;i<ts.length;i++){ts[i]=new Thread(()->{for(int j=0;j<1000;j++)if(Targets.chain(j)!=6*j+17)errors.incrementAndGet();});ts[i].start();}for(Thread t:ts)t.join();check(errors.get()==0);});
        System.out.println("AOT_CALL_FIXTURE passed="+passed+" failed="+failed);
        if(failed!=0)System.exit(1);
    }
}
