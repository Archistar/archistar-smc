package at.archistar.crypto.math;

import at.archistar.crypto.exceptions.ReconstructionException;

/**
 * Helper class for solving a polynomial
 *
 * @author Andreas Happe <andreashappe@snikt.net>
 */
public class PolyGF256 {

    public static byte reconstructLagrangeConstantCoeff(int xValues[], int yValues[]) {
        assert xValues.length == yValues.length;

        int secret = 0;

        //Calculate the restored byte from each share
        for (int j = 0; j < xValues.length; j++) {
            int y = yValues[j];
            int xj = xValues[j];
            int tmp = 1;

            for (int g = 0; g < xValues.length; g++) {
                if (j != g) {
                    int x = xValues[g];
                    /* tmp = tmp * (x_g / (x_g - x_j)) */
                    tmp = GF256.mult(tmp, GF256.div(x, GF256.sub(x, xj)));
                }
            }
            /* secret = secret + y_g * tmp */
            secret = GF256.add(secret, GF256.mult(y, tmp));
        }
        return (byte) (secret & 0xFF);
    }

    public static int[] simpleErasureDecode(int x[], int yValues[]) throws ReconstructionException {

        int[][] matrixX = new int[x.length][x.length];
        for (int i = 0; i < yValues.length; i++) {
            for (int j = 0; j < yValues.length; j++) {
                assert (x[i] >= 0);
                matrixX[i][j] = GF256.pow(x[i], j);
            }
        }

        CustomMatrix xX = new CustomMatrix(matrixX);
        de.flexiprovider.common.math.linearalgebra.Matrix anotherMatrix = xX.computeInverse();
        xX = new CustomMatrix(anotherMatrix.getEncoded());
        return xX.rightMultiply(yValues);
    }

    public static CustomMatrix erasureDecodePrepare(int x[]) throws ReconstructionException {

        int[][] matrixX = new int[x.length][x.length];
        for (int i = 0; i < x.length; i++) {
            for (int j = 0; j < x.length; j++) {
                assert (x[i] >= 0);
                matrixX[i][j] = GF256.pow(x[i], j);
            }
        }

        CustomMatrix xX = new CustomMatrix(matrixX);
        de.flexiprovider.common.math.linearalgebra.Matrix anotherMatrix = xX.computeInverse();
        xX = new CustomMatrix(anotherMatrix.getEncoded());
        return xX;
    }
}
