package at.archistar.crypto.informationchecking;

import at.archistar.crypto.data.Share;

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
     */
    public Share[] checkShares(Share[] shares);
    
    /**
     * @param shares the shares that need IC information to be added
     * @return shares with information checking data
     */
    public Share[] createTags(Share[] shares);
}
