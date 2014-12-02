package at.archistar.crypto.informationchecking;

import at.archistar.crypto.data.Share;
import java.io.IOException;

/**
 * @author andy
 */
public interface InformationChecking {
    
    public Share[] checkShares(Share[] cshares) throws IOException;
    
    public void createTags(Share[] rboshares) throws IOException;
}
