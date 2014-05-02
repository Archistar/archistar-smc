package at.archistar.crypto.random;

import java.util.Random;

/**
 * Wrapper for normal java random generator
 *
 * @author Andreas Happe <andreashappe@snikt.net>
 */
public class JavaRandomSource implements RandomSource {

    private static Random rnd;

    public JavaRandomSource() {
        rnd = new Random();
    }

    @Override
    public int generateByte() {
        return rnd.nextInt(255) + 1;
    }
}
