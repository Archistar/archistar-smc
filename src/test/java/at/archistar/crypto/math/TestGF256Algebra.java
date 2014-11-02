package at.archistar.crypto.math;

import at.archistar.crypto.math.gf256.GF256;
import org.bouncycastle.pqc.math.linearalgebra.GF2mField;

import java.util.Set;
import java.util.HashSet;
import java.util.BitSet;

import static org.junit.Assert.*;
import org.junit.Ignore;
import org.junit.Test;

public class TestGF256Algebra {
  private final Field<Integer> gf256Abstract;
  private static Field<Integer> gf256ACache;
  private final GF256 gf256 = new GF256();
  private final GF2mField ref = new GF2mField( 8, 0x11d);
  private static final int SIZE = 256;
  private final int ZERO;
  private final int UNITY;
  
  {
    if ( null == gf256ACache ) {
      Set<Integer> S = new HashSet<>( SIZE);
      for ( int i = 0; i < SIZE; ++ i )
	S.add( i);
      BinOp<Integer> addOp = new AddOp( S);
      BinOp<Integer> mulOp = new MulOp( S);
      // this constructor will verify all the properties needed for a field
      gf256ACache = new Field<Integer>( addOp, mulOp);
    }
    gf256Abstract = gf256ACache;
    ZERO = gf256Abstract.identity;
    UNITY = gf256Abstract.unity;
  }
  
  class AddOp extends BinOp<Integer> {
    AddOp( Set<Integer> S) { super( S); }
    Integer eval( Integer a, Integer b) {
      return gf256.add( a, b);
    }
  }
  
  class MulOp extends BinOp<Integer> {
    MulOp( Set<Integer> S) { super( S); }
    Integer eval( Integer a, Integer b) {
      return gf256.mult( a, b);
    }
  }
  
  @Test
  public void testMultVsBC() {
    System.err.println( "Testing mult agreement with BouncyCastle");
    for ( int a = 0 ; a < SIZE ; ++ a ) {
      for ( int b = 0 ; b < SIZE ; ++ b ) {
        int r = gf256.mult( a, b);
	int rref = ref.mult( a, b);
	if ( r != rref )
	  fail( String.format( "mult vs. BC disagree: %d*%d -> %d or %d",
	        a, b, r, rref));
      }
    }
  }

  @Test
  public void testPow() {
    System.err.println( "Testing pow correspondence with mult");
    BitSet bits = new BitSet( SIZE);
    for ( int a = 0 ; a < SIZE ; ++ a ) {
      int prod = UNITY;
      for ( int p = 0 ; p < SIZE ; ++ p ) {
        int r = gf256.pow( a, p);
	if ( r != prod )
	  fail( String.format( "pow and mult disagree: %d^%d -> %d or %d",
	        a, p, r, prod));
	if ( bits.get( r) )
	  break;
	bits.set( r);
	prod = gf256.mult( prod, a);
      }
      bits.clear();
    }
  }
  
  @Test
  public void testInverse() {
    System.err.println( "Testing inverse correspondence with mult");
    for ( int a = 0 ; a < SIZE ; ++ a ) {
      if ( ZERO == a )
        continue;
      int inv = gf256.inverse( a);
      if ( UNITY != gf256.mult( a, inv) || UNITY != gf256.mult( inv, a) )
        fail( String.format( "inverse fails for %d", a));
    }
  }
  
  @Test
  public void testDiv() {
    System.err.println( "Testing div correspondence with mult");
    for ( int a = 0 ; a < SIZE ; ++ a ) {
      for ( int b = 0 ; b < SIZE ; ++ b ) {
        if ( ZERO == b )
	  continue;
	int q = gf256.div( a, b);
	int p = gf256.mult( q, b);
	if ( a != p )
	  fail( String.format( "%d/%d -> %d but %d*%d -> %d",
	        a, b, q, q, b, p));
      }
    }
  }
}
