package at.archistar.crypto;

public class TestHelper {
    public static byte[][] createArray(int size, int elementSize) {
        byte[][] result = new byte[size / elementSize][elementSize];

        for (int i = 0; i < size / elementSize; i++) {
            for (int j = 0; j < elementSize; j++) {
                result[i][j] = 42;
            }
        }

        return result;
    }
}
