package helper;

import at.archistar.crypto.data.Share;

/**
 * This is a little helper-class for extracting and initializing information parallel from an array of shares.<br>
 * The main purpose reuse and clean up code in the Secret-Sharing implementations.
 * 
 * @author Elias Frantar
 * @version 2014-7-14
 */
public class ShareHelper {
	private ShareHelper() {} // we don't want any instances of that class
	
	/**
	 * Extracts all x-values from the given array of shares.
	 * @param shares the shares to extract the values from
	 * @return an array of all x-values (in same order as the passed Share-array)
	 */
	public static int[] extractXVals(Share[] shares) {
		int[] xVals = new int[shares.length];
		for(int i = 0;i < xVals.length;i++)
			xVals[i] = shares[i].getX();
		
		return xVals;
	}
	
	/**
	 * Extracts all <i>i<sup>th</sup></i> y-values from the given array of shares.
	 * @param shares the shares to extract the values from
	 * @param index the index of the values to extract
	 * @return an array of all <i>i<sup>th</sup></i> y-values (in same order as the passed Share-array)
	 */
	public static int[] extractYVals(Share[] shares, int index) {
		int[] yVals = new int[shares.length];
		for(int i = 0;i < shares.length;i++)
			yVals[i] = shares[i].getY(index);
		
		return yVals;
	}
	
	/**
	 * Initializes all shares for adding MACs. (happens by calling {@link Share#initForMac(int, int, int)} for every share)
	 * @param shares the shares to initialize
	 * @param tagLength the length of each individual MAC-tag
	 * @param keyLength the length of each MAC-key (usually equals tagLength)
	 */
	public static void initForMacs(Share[] shares, int tagLength, int keyLength) {
		for(Share s : shares)
			s.initForMac(shares.length, tagLength, keyLength);
	}
	
}