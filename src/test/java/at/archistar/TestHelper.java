package at.archistar;

import at.archistar.crypto.data.Share;

/**
 * commonly needed test functionality
 */
public class TestHelper {

    /** test size for slow-running tests */
    public static final int REDUCED_TEST_SIZE = 4 * 1024 * 1024;

    /** test size for normal tests */
    public static final int TEST_SIZE = 10 * REDUCED_TEST_SIZE;

    /**
     * create test data
     *
     * @param elementSize fragment size in byte, this will create an array with
     * elements sized "elementsSize" and a total size of TEST_SIZE
     * @return test data
     */
    public static byte[][] createArray(int elementSize) {
        return createArray(TEST_SIZE, elementSize);
    }

    /**
     * create test data
     *
     * @param size overall test data size
     * @param elementSize fragment size in byte, this will create an array with
     * elements sized "elementsSize" and a total size of "size"
     * @return test data
     */
    public static byte[][] createArray(int size, int elementSize) {
        byte[][] result = new byte[size / elementSize][elementSize];

        for (int i = 0; i < size / elementSize; i++) {
            for (int j = 0; j < elementSize; j++) {
                result[i][j] = 1;
            }
        }

        return result;
    }

    /**
     * drop the array element at the specified index
     *
     * @param shares the array to drop from
     * @param i the index of the element to drop
     * @return a new array without the element at the specified index
     */
    public static Share[] dropElementAt(Share[] shares, int i) {
        Share[] res = new Share[shares.length - 1];
        int pos = 0;
        for (int x = 0; x < shares.length; x++) {
            if (x != i) {
                res[pos++] = shares[x];
            }
        }
        return res;
    }
}
