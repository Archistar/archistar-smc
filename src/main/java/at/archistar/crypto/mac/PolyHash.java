package at.archistar.crypto.mac;

import at.archistar.crypto.math.GF;
import at.archistar.crypto.math.GenericPolyHelper;
import java.security.InvalidKeyException;
import java.util.Arrays;

/**
 * a very simple polynomial hash implementation for cevallos
 */
public class PolyHash implements MacHelper {

    private final int keylength;

    private final GF gf;
    
    private final GenericPolyHelper polyHelper;

    public PolyHash(int keylength, GF gf) {
        this.keylength = keylength;
        this.polyHelper = new GenericPolyHelper(gf);
        this.gf = gf;
    }

    private static int[] createIntArrayFromByte(byte[] a) {
        int[] b = new int[a.length];
        for (int i = 0; i < a.length; i++) {
            b[i] = a[i];
        }
        return b;
    }

    @Override
    public byte[] computeMAC(byte[] data, byte[] key) throws InvalidKeyException {

        assert (this.keylength * 2 == key.length);

        int b[] = createIntArrayFromByte(Arrays.copyOf(key, this.keylength));

        /* set a to be the other part of the key */
        int[] a = createIntArrayFromByte(Arrays.copyOfRange(key, this.keylength, key.length));

        /* set result's bits to the first keylength elements */
        int[] result = createIntArrayFromByte(Arrays.copyOf(data, this.keylength));

        int rowCount = data.length / this.keylength;

        /* reihenfolge innerhalb des arrays sollte ja wurscht sein */
        for (int i = 1; i < rowCount; i++) {
            int[] next = createIntArrayFromByte(Arrays.copyOfRange(data, i * this.keylength, (i + 1) * this.keylength));
            result = polyHelper.multiply(result, polyHelper.add(b, next));
        }

        /* add rest -> reihenfolge wurscht, sollt also funktionieren */
        if (data.length % this.keylength != 0) {
            int[] next = createIntArrayFromByte(Arrays.copyOfRange(data, rowCount * this.keylength, data.length));

            /* expand to keylength */
            next = Arrays.copyOf(next, keylength);
            System.err.println("" + result.length + " vs " + next.length);
            result = polyHelper.add(result, next);
        }

        /* add a */
        System.err.println("" + result.length + " vs " + a.length);
        result = polyHelper.add(result, a);

        /* extract result into a byte[] array */
        byte[] byteResult = new byte[this.keylength];
        for (int i = 0; i < result.length; i++) {
            byteResult[i] = (byte) result[i];
        }
        return byteResult;
    }

    @Override
    public boolean verifyMAC(byte[] data, byte[] tag, byte[] key) {
        boolean valid = false;

        try {
            byte[] newTag = computeMAC(data, key); // compute tag for the given parameters
            valid = Arrays.equals(tag, newTag); // compare with original tag
        } finally {
            return valid;
        }
    }

    @Override
    public int keySize() {
        // a and b
        return this.keylength * 2;
    }
}
