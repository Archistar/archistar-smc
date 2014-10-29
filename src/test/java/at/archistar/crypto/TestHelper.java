package at.archistar.crypto;

public class TestHelper {

    public static final int REDUCED_TEST_SIZE = 4 * 1024 * 1024;

    public static final int TEST_SIZE = 25 * REDUCED_TEST_SIZE;
    
    public static byte[][] createArray(int elementSize) {
        return createArray(TEST_SIZE, elementSize);
    }

    public static byte[][] createArray(int size, int elementSize) {
        byte[][] result = new byte[size / elementSize][elementSize];

        for (int i = 0; i < size / elementSize; i++) {
            for (int j = 0; j < elementSize; j++) {
                result[i][j] = 1;
            }
        }

        return result;
    }
}
