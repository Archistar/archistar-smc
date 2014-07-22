package at.archistar.crypto.exceptions;

/**
 * A 'this-can-never-happen'-Exception
 *
 * @author Elias Frantar <i>(added documentation)</i>
 * @author andy
 * @version 2014-7-21
 */
public class ImpossibleException extends RuntimeException {
    private static final long serialVersionUID = 7368039150868763444L;
    
    private String msg;

    /**
     * Constructor
     * @param msg the message to deliver with this Exception
     */
    public ImpossibleException(String msg) {
        this.msg = msg;
    }

    /**
     * Constructor
     * @param e the Exception to wrap into this Exception
     */
    public ImpossibleException(Exception e) {
        e.printStackTrace();
        this.msg = e.getMessage();
    }

    @Override
    public String toString() {
        return "Exception: " + msg;
    }
}
