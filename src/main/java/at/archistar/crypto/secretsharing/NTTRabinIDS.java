package at.archistar.crypto.secretsharing;

import at.archistar.crypto.data.Share;
import at.archistar.crypto.data.Share.ShareType;
import at.archistar.crypto.decode.DecoderFactory;
import at.archistar.crypto.math.GFFactory;
import at.archistar.crypto.math.ntt.AbstractNTT;

/**
 * perform reed-solomon coding using NTT
 */
public class NTTRabinIDS extends NTTSecretSharing {

    /**
     * create a new NTTRabinIDS secret-sharing
     * 
     * @param n amount of shares to be generated
     * @param k minimum amount of shares for reconstruction
     * @param generator the generator
     * @param factory the field within which we're working (should be GF257 for now)
     * @param ntt the ntt used for computation (shoudl be |gf|+1)
     * @param decoderFactory the decoder that will be used for the reconstruction step
     */
    public NTTRabinIDS(int n, int k, int generator,
                       GFFactory factory,
                       AbstractNTT ntt,
                       DecoderFactory decoderFactory) throws WeakSecurityException {
        
        super(n, k, generator, factory, ntt, decoderFactory);
        
        shareSize = nttBlockLength / n;
        dataPerNTT = nttBlockLength / n * k;
    }
    
    @Override
    protected int[] encodeData(int tmp[], int[] data, int offset, int length) {
        System.arraycopy(data, offset, tmp, 0, length);
        return tmp;
    }

    @Override
    protected Share.ShareType getShareType() {
        return ShareType.NTT_RABIN_IDS;
    }
    
    /**
     * @return human-readable description of this secret-sharing scheme
     */
    @Override
    public String toString() {
        return "NTTRabinIDS(" + n + "/" + k + ", NTTLength: " + nttBlockLength +")";
    }
}
