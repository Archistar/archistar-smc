package at.archistar.crypto.data;

import at.archistar.crypto.secretsharing.ReconstructionException;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

import java.util.Collections;
import java.util.List;

/**
 * The result of a reconstruction operation
 * (CryptoEngine::reconstruct or CryptoEngine::reconstructPartial)
 * <p>
 * This encapsulation was necessary because a reconstruction can not
 * only cleanly succeed or fail. If Shares are validated, reconstruction
 * can succeed even when some Shares are faulty. In these cases we want
 * to propagate the errors and we did not want to (mis)use Exceptions for
 * this
 *
 * @author florian
 */
public class ReconstructionResult {

    private final byte[] data;
    private final boolean okay;
    private final List<String> errors;

    @SuppressFBWarnings("EI_EXPOSE_REP2")
    public ReconstructionResult(byte[] data) {
        this.data = data;
        this.okay = true;
        this.errors = Collections.emptyList();
    }

    public ReconstructionResult(List<String> errors) {
        this.data = new byte[0];
        this.okay = false;
        this.errors = errors;
    }

    @SuppressFBWarnings("EI_EXPOSE_REP2")
    public ReconstructionResult(byte[] data, List<String> errors) {
        this.data = data;
        this.okay = true;
        this.errors = errors;
    }

    @SuppressFBWarnings("EI_EXPOSE_REP")
    public byte[] getData() throws ReconstructionException {
        if (okay) {
            return data;
        } else {
            throw new ReconstructionException();
        }
    }

    public boolean isOkay() {
        return okay;
    }

    public List<String> getErrors() {
        return errors;
    }
}
