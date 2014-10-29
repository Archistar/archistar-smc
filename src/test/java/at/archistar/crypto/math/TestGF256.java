package at.archistar.crypto.math;

import at.archistar.crypto.math.bc.BCGF256;
import at.archistar.crypto.math.gf256.GF256;
import static org.fest.assertions.api.Assertions.*;

import org.junit.Test;

/**
 * <p>
 * A simple unit-test for {@link GF256} and {@link BCGF256}.</p>
 */
public class TestGF256 {
    private final BCGF256 gf256 = new BCGF256();

    private final GF256 gf = new GF256();

    @Test
    public void testAdd() {
        for (int i = 0; i < gf.getFieldSize(); i++) {
            for (int j = 0; j < gf.getFieldSize(); j++) {
                int tmp = gf.add(i, j);
                assertThat(gf256.add(i, j)).isEqualTo(tmp);
                assert (tmp >= 0 && tmp < gf.getFieldSize());
            }
        }
    }

    @Test
    public void testSubtract() {
        for (int i = 0; i < gf.getFieldSize(); i++) {
            for (int j = 0; j < gf.getFieldSize(); j++) {
                int tmp = gf.sub(i, j);
                assertThat(gf256.sub(i, j)).isEqualTo(tmp);
                assert (tmp >= 0 && tmp < gf.getFieldSize());
            }
        }
    }

    @Test
    public void testMult() {
        for (int i = 0; i < gf.getFieldSize(); i++) {
            for (int j = 0; j < gf.getFieldSize(); j++) {
                int tmp = gf.mult(i, j);
                assertThat(gf256.mult(i, j)).isEqualTo(tmp);
                assert (tmp >= 0 && tmp < gf.getFieldSize());
            }
        }
    }

    @Test
    public void testDiv() {
        for (int i = 0; i < gf.getFieldSize(); i++) {
            for (int j = 1; j < gf.getFieldSize(); j++) {
                int tmp = gf.div(i, j);
                assertThat(gf256.div(i, j)).isEqualTo(tmp);
                assert (tmp >= 0 && tmp < gf.getFieldSize());
            }
        }
    }

    @Test
    public void testInverse() {
        for (int i = 1; i < gf.getFieldSize(); i++) {
            int tmp = gf.inverse(i);
            assertThat(gf256.inverse(i)).isEqualTo(tmp);
            assert (tmp >= 0 && tmp < gf.getFieldSize());
        }
    }

    @Test
    public void testInverseValue() {
        for (int i = 1; i < gf.getFieldSize(); i++) {
            assertThat(gf.mult(gf.inverse(i), i) == 1);
            assertThat(gf256.mult(gf256.inverse(i), i) == 1);
        }
    }

    @Test
    public void testPow() {
        for (int i = 0; i < gf.getFieldSize(); i++) {
            for (int j = 0; j < 8; j++) {
                if (i != 0 && j != 0) {
                    int tmp = gf.pow(i, j);
                    assertThat(gf256.pow(i, j)).isEqualTo(tmp);
                    assert (tmp >= 0 && tmp < gf.getFieldSize());
                }
            }
        }
    }

    @Test
    public void testEvaluate() {

        final int[] coeffs = {1, 2, 3, 4, 5, 6};

        for (int x = 1; x < gf.getFieldSize(); x++) {
            assertThat(gf256.evaluateAt(coeffs, x)).isEqualTo(gf.evaluateAt(coeffs, x));
        }
    }
}
