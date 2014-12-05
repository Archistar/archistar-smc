package at.archistar.crypto.informationchecking;

import at.archistar.crypto.data.Share;
import java.io.IOException;

/**
 * An information checking algorithm takes a collection of shares and adds
 * share validation information. It's suspected of setting the share's
 * informationChecking, macKeys and macs member variables. In addition it is
 * free to add additional data to the share's metadata collection.
 */
public interface InformationChecking {

    /**
     * 
     * @param shares the shares with IC information to be checked
     * @return the shares that passed the IC check
     * @throws IOException 
     */
    public Share[] checkShares(Share[] shares) throws IOException;
    
    /**
     * @param shares the shares that need IC information to be added
     * @throws IOException 
     */
    public void createTags(Share[] shares) throws IOException;
}
