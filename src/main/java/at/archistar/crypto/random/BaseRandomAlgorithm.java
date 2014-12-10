package at.archistar.crypto.random;

/**
 * Move common used functionality into this abstract base class
 */
abstract class BaseRandomAlgorithm implements RandomSource {
    
    protected byte[] cache = new byte[0];
    
    protected int counter = Integer.MAX_VALUE;
    
    @Override
    public void fillBytes(byte[] toBeFilled) {
        for (int i = 0; i < toBeFilled.length; i++) {
            toBeFilled[i] = (byte)generateByte();
        }
    }
    
    @Override
    public void fillBytesAsInts(int[] toBeFilled) {
        for (int i = 0; i < toBeFilled.length; i++) {
            toBeFilled[i] = generateByte();
        }
    }
    
    /**
     * generates the next random byte
     * 
     * @return a new random byte
     */
    protected int generateByte() {
        
        byte b;
        do {
            if (counter > cache.length - 1) {
                fillCache();
            }
        } while ((b = cache[counter++]) == 0); // result must not be 0
        
        return b & 0xff;
    }
    
    protected abstract void fillCache();
}
