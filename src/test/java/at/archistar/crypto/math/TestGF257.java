package at.archistar.crypto.math;

import at.archistar.crypto.math.gf257.GF257;

import static org.fest.assertions.api.Assertions.assertThat;

import org.junit.Test;

/**
 * @author andy
 */
public class TestGF257 {

    private final GF257 gf = new GF257();

    @Test
    public void testAdd() {
        for (int i = 0; i < gf.getFieldSize(); i++) {
            for (int j = 0; j < gf.getFieldSize(); j++) {
                int tmp = gf.add(i, j);
                assertThat(tmp).isGreaterThanOrEqualTo(0);
                assertThat(tmp).isLessThan(gf.getFieldSize());
            }
        }
    }

    @Test
    public void testSubtract() {
        for (int i = 0; i < gf.getFieldSize(); i++) {
            for (int j = 0; j < gf.getFieldSize(); j++) {
                int tmp = gf.sub(i, j);
                assertThat(tmp).isGreaterThanOrEqualTo(0);
                assertThat(tmp).isLessThan(gf.getFieldSize());
            }
        }
    }

    @Test
    public void testMult() {
        for (int i = 0; i < gf.getFieldSize(); i++) {
            for (int j = 0; j < gf.getFieldSize(); j++) {
                int tmp = gf.mult(i, j);
                assertThat(tmp).isGreaterThanOrEqualTo(0);
                assertThat(tmp).isLessThan(gf.getFieldSize());
            }
        }
    }

    @Test
    public void testDiv() {
        for (int i = 0; i < gf.getFieldSize(); i++) {
            for (int j = 1; j < gf.getFieldSize(); j++) {
                int tmp = gf.div(i, j);
                assert (tmp >= 0 && tmp < gf.getFieldSize());
            }
        }
    }

    @Test
    public void testInverse() {
        for (int i = 1; i < gf.getFieldSize(); i++) {
            int tmp = gf.inverse(i);
            assertThat(tmp).isGreaterThanOrEqualTo(0);
            assertThat(tmp).isLessThan(gf.getFieldSize());
        }
    }

    @Test
    public void testInverseValue() {
        for (int i = 1; i < gf.getFieldSize(); i++) {
            assertThat(gf.mult(gf.inverse(i), i)).isEqualTo(1);
        }
    }

    @Test
    public void testPow() {
        for (int i = 0; i < gf.getFieldSize(); i++) {
            for (int j = 0; j < 8; j++) {
                if (i != 0 && j != 0) {
                    int tmp = gf.pow(i, j);
                    assertThat(tmp).isGreaterThanOrEqualTo(0);
                    assertThat(tmp).isLessThan(gf.getFieldSize());
                }
            }
        }
    }
}
