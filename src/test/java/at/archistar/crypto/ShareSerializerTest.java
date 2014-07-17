package at.archistar.crypto;

import static org.junit.Assert.*;
import helper.ShareSerializer;

import org.junit.Test;

import at.archistar.crypto.data.Share;

/**
 * Test the serialization and deserialization of {@link ShareSerializer}
 * @author Elias Frantar
 * @version 2014-7-17
 */
public class ShareSerializerTest {
	
	@Test
	public void testShamirShare() {
		Share s = new Share(Share.SHAMIR);
		s.setX((byte) 10);
		s.setY(new byte[]{1, 2, 3, 4, 5});
		
		byte[] serialized = ShareSerializer.serializeShare(s);
		
		assertEquals(s, ShareSerializer.deserializeShare(serialized));
	}
	
	@Test
	public void testReedSolomonShare() {
		Share s = new Share(Share.REED_SOLOMON);
		s.setX((byte) 10);
		s.setY(new byte[]{1, 2, 3, 4, 5});
		s.setOriginalLength(25);
		
		byte[] serialized = ShareSerializer.serializeShare(s);
		
		assertEquals(s, ShareSerializer.deserializeShare(serialized));
	}
	
	@Test
	public void testKrawczykShare() {
		Share s = new Share((byte) (Share.KRAWCZYK | Share.REED_SOLOMON));
		s.setX((byte) 10);
		s.setY(new byte[]{1, 2, 3, 4, 5});
		s.setOriginalLength(25);
		s.setKeyY(new byte[]{10, 9, 8, 7, 6});
		
		byte[] serialized = ShareSerializer.serializeShare(s);
		
		assertEquals(s, ShareSerializer.deserializeShare(serialized));
	}
	
	@Test
	public void testRabinBenOrShare() {
		Share s = new Share((byte) (Share.RABIN_BEN_OR | Share.KRAWCZYK | Share.REED_SOLOMON));
		s.setX((byte) 10);
		s.setY(new byte[]{1, 2, 3, 4, 5});
		s.setOriginalLength(25);
		s.setKeyY(new byte[]{10, 9, 8, 7, 6});
		
		s.initForMac(3, 2, 2);
		
		s.setMacKey((byte) 1, new byte[]{1, 2});
		s.setMacKey((byte) 2, new byte[]{3, 4});
		s.setMacKey((byte) 3, new byte[]{5, 6});
		s.setTag((byte) 1, new byte[]{7, 8});
		s.setTag((byte) 2, new byte[]{9, 10});
		s.setTag((byte) 3, new byte[]{11, 12});
		
		byte[] serialized = ShareSerializer.serializeShare(s);
		
		assertEquals(s, ShareSerializer.deserializeShare(serialized));
	}
	
	@Test
	public void testUSRSSShare() {
		Share s = new Share((byte) Share.USRSS);
		s.setX((byte) 10);
		s.setY(new byte[]{1, 2, 3, 4, 5});
		
		s.initForMac(3, 2, 2);
		
		s.setMacKey((byte) 1, new byte[]{1, 2});
		s.setMacKey((byte) 2, new byte[]{3, 4});
		s.setMacKey((byte) 3, new byte[]{5, 6});
		s.setTag((byte) 1, new byte[]{7, 8});
		s.setTag((byte) 2, new byte[]{9, 10});
		s.setTag((byte) 3, new byte[]{11, 12});
		
		byte[] serialized = ShareSerializer.serializeShare(s);
		
		assertEquals(s, ShareSerializer.deserializeShare(serialized));
	}
}