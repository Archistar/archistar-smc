package at.archistar.crypto.secretsharing;

import at.archistar.crypto.data.Share;
import at.archistar.crypto.data.Share.ShareType;
import at.archistar.crypto.decode.DecoderFactory;
import at.archistar.crypto.exceptions.WeakSecurityException;
import at.archistar.crypto.math.GFFactory;
import at.archistar.crypto.math.ntt.AbstractNTT;

/**
 *
 * @author andy
 */
public class NTTRabinIDS extends NTTSecretSharing {
    
    public NTTRabinIDS(int n, int k, int generator, GFFactory factory, AbstractNTT ntt, DecoderFactory decoderFactory) throws WeakSecurityException {
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
        return ShareType.NTT_REED_SOLOMON;
    }
}
