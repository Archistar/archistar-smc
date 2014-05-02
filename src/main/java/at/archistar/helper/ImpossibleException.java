package at.archistar.helper;

/**
 * This will be used for 'this-can-never-happen' exceptions;
 *
 * @author andy
 */
public class ImpossibleException extends RuntimeException {

    private String msg;

    /**
     *
     */
    private static final long serialVersionUID = 7368039150868763444L;

    public ImpossibleException(String msg) {
        this.msg = msg;
    }

    public ImpossibleException(Exception e) {
        e.printStackTrace();
        this.msg = e.getMessage();
    }

    @Override
    public String toString() {
        return "exception: " + msg;
    }
}
