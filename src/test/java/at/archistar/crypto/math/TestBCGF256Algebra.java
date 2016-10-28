package at.archistar.crypto.math;

import org.bouncycastle.pqc.math.linearalgebra.GF2mField;

import java.util.Set;
import java.util.HashSet;
import java.util.BitSet;

import static org.junit.Assert.*;

import org.junit.Test;
import org.junit.Ignore;

public class TestBCGF256Algebra {
    private final Field<Integer> gf256Abstract;
    private static Field<Integer> gf256ACache;
    private final GF2mField gf256 = new GF2mField(8, 0x11d);
    private static final int SIZE = 256;
    private final int ZERO;
    private final int UNITY;

    {
        if (null == gf256ACache) {
            Set<Integer> S = new HashSet<>(SIZE);
            for (int i = 0; i < SIZE; ++i)
                S.add(i);
            BinOp<Integer> addOp = new AddOp(S);
            BinOp<Integer> mulOp = new MulOp(S);
            // this constructor will verify all the properties needed for a field
            gf256ACache = new Field<Integer>(addOp, mulOp);
        }
        gf256Abstract = gf256ACache;
        ZERO = gf256Abstract.identity;
        UNITY = gf256Abstract.unity;
    }

    class AddOp extends BinOp<Integer> {
        AddOp(Set<Integer> S) {
            super(S);
        }

        Integer eval(Integer a, Integer b) {
            return gf256.add(a, b);
        }
    }

    class MulOp extends BinOp<Integer> {
        MulOp(Set<Integer> S) {
            super(S);
        }

        Integer eval(Integer a, Integer b) {
            return gf256.mult(a, b);
        }
    }

    @Test
    @Ignore // anything^ZERO === UNITY but BC exp(0,0) returns ZERO
    public void testExp() {
        System.err.println("Testing exp correspondence to mult");
        BitSet bits = new BitSet(SIZE);
        for (int a = 0; a < SIZE; ++a) {
            int prod = UNITY;
            for (int p = 0; p < SIZE; ++p) {
                int r = gf256.exp(a, p);
                if (r != prod)
                    fail(String.format("exp and mult disagree: %d^%d -> %d or %d",
                            a, p, r, prod));
                if (bits.get(r))
                    break;
                bits.set(r);
                prod = gf256.mult(prod, a);
            }
            bits.clear();
        }
    }
}
