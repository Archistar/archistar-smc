package at.archistar.crypto.data;

import java.util.Map;

/**
 * @author florian
 */
public interface InformationCheckingShare extends Share {

    /**
     * which information checking schemas can we work with?
     */
    enum ICType {
        /** rabin-ben-or with fixed hashes */
        RABIN_BEN_OR,
        /** cevallos with dynamic length hashes */
        CEVALLOS
    }

    /**
     * @return macs used during secret checking (TODO: add sane interface)
     */
    Map<Byte, byte[]> getMacs();

    /**
     * @return keys used during secret checking (TODO: add sane interface)
     */
    Map<Byte, byte[]> getMacKeys();

    /**
     *
     * @return the information checking algorithm used
     */
    ICType getICType();
}
