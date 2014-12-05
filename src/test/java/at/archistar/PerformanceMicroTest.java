package at.archistar;

import java.util.Arrays;
import java.util.Collection;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

/**
 * Various java-level micro performance tests
 */
@RunWith(value = Parameterized.class)
public class PerformanceMicroTest {
    
    private final byte[] data;
    
    private final long count = 10000000;
    
   @Parameterized.Parameters
    public static Collection<Object[]> data() {
        Object[][] data = new Object[][]{
           { new byte[1] },
           { new byte[3] },
           { new byte[128] },
           { new byte[1024] },
           { new byte[4096] }
        };

        return Arrays.asList(data);
    }
    
    public PerformanceMicroTest(byte[] input) {
        this.data = input;
    }

    /**
     * test which array copy method is fastest
     * 
     * 2014-12-3 java7 seems like System.arraycopy is overall the fastest
     */
    @Test
    @Ignore("very slow")
    public void testArrayClone() {
        
        long before, after;
        
        double sumClone = 0;
        double sumArraysCopyOf = 0;
        double sumSystemCopyAlloc = 0;
        double sumSystemCopy = 0;
        double sumIterate = 0;
        double sumIterateAlloc = 0;
        
        for (long i = 0; i < count; i++) {
            before = System.currentTimeMillis();
            data.clone();
            after = System.currentTimeMillis();

            sumClone += (after - before);
        }
        
        for (long i = 0; i < count; i++) {
            before = System.currentTimeMillis();
            Arrays.copyOf(data, data.length);
            after = System.currentTimeMillis();

            sumArraysCopyOf += (after - before);
        }
        
        for (long i = 0; i < count; i++) {
            before = System.currentTimeMillis();
            byte[] tmp = new byte[data.length];
            System.arraycopy(data, 0, tmp, 0, data.length);
            after = System.currentTimeMillis();

            sumSystemCopyAlloc += (after - before);
        }
        
        for (long i = 0; i < count; i++) {
            before = System.currentTimeMillis();
            byte[] tmp = new byte[data.length];
            for (int j = 0; j < data.length; j++) {
                tmp[j] = data[j];
            }
            after = System.currentTimeMillis();

            sumIterateAlloc += (after - before);
        }

        byte[] tmp = new byte[data.length];
        for (long i = 0; i < count; i++) {
            before = System.currentTimeMillis();
            System.arraycopy(data, 0, tmp, 0, data.length);
            after = System.currentTimeMillis();

            sumSystemCopy += (after - before);
        }
        
        for (long i = 0; i < count; i++) {
            before = System.currentTimeMillis();
            for (int j = 0; j < data.length; j++) {
                tmp[j] = data[j];
            }
            after = System.currentTimeMillis();

            sumIterate += (after - before);
        }
        
        System.out.println("### Array size: " + data.length);
        System.out.format("array.copyOf/clone: %.04f\n", sumArraysCopyOf/sumClone);
        System.out.format("System.arraycopy+alloc/clone: %.04f\n", sumSystemCopyAlloc/sumClone);
        System.out.format("System.arraycopy/clone: %.04f\n", sumSystemCopy/sumClone);
        System.out.format("Array.iterate+alloc/clone: %.04f\n", sumIterateAlloc/sumClone);
        System.out.format("Array.iterate/clone: %.04f\n", sumIterate/sumClone);
        System.out.println("");
    }
}
