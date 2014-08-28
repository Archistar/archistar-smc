package at.archistar.crypto.informationchecking;

import at.archistar.crypto.data.Share;
import at.archistar.crypto.data.VSSShare;
import java.io.IOException;

/**
 * WIP: I really want to move cevallos & rabinbenor away from SecretSharing
 *      towards this interface.
 * 
 * @author andy
 */
public interface InformationChecking {
    
    public Share[] checkShares(VSSShare[] cshares) throws IOException;
    
    public void createTags(VSSShare[] rboshares) throws IOException;
}
