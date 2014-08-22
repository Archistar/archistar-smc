package at.archistar.crypto.data;

/**
 *
 * @author andy
 */
public abstract class BaseShare implements Share {
        /**
     * Extracts all x-values from the given Share[].
     * @param shares the shares to extract the x-values from
     * @return an array with all x-values from the given shares (in same order as the given Share[])
     */
    public static int[] extractXVals(Share[] shares) {
        int[] x = new int[shares.length];
        
        for (int i = 0; i < x.length; i++) {
            x[i] = shares[i].getId();
        }
        
        return x;
    }
}
