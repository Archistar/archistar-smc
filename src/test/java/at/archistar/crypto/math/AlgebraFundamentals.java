package at.archistar.crypto.math;

import java.util.Set;
import java.util.HashSet;

import static org.junit.Assert.*;

import org.junit.Test;

abstract class BinOp<T> {
    final Set<T> S;

    abstract T eval(T a, T b);

    BinOp(Set<T> S) {
        this.S = S;
        System.err.println("Testing closure under " + getClass().getName());
        for (T a : S) {
            for (T b : S) {
                assertTrue("Not closed under operation", S.contains(eval(a, b)));
                assertTrue("Not closed under operation", S.contains(eval(b, a)));
            }
        }
    }

    Set<T> getS() {
        return S;
    }

    boolean commutative() {
        System.err.println("Testing commutativity of " + getClass().getName());
        for (T a : S) {
            for (T b : S) {
                if (!eval(a, b).equals(eval(b, a)))
                    return false;
            }
        }
        return true;
    }

    boolean associative() {
        System.err.println("Testing associativity of " + getClass().getName());
        for (T a : S) {
            for (T b : S) {
                for (T c : S) {
                    if (!eval(a, eval(b, c)).equals(eval(eval(a, b), c)))
                        return false;
                }
            }
        }
        return true;
    }

    T identity() {
        System.err.println("Testing for identity under " + getClass().getName());
        e:
        for (T e : S) {
            for (T a : S) {
                if (!a.equals(eval(a, e)))
                    continue e;
                if (!a.equals(eval(e, a)))
                    continue e;
            }
            return e;
        }
        return null;
    }

    boolean inverses(T e, T except) {
        System.err.println("Testing for inverses under " + getClass().getName());
        Set<T> unpaired = new HashSet<>(S);
        if (null != except)
            unpaired.remove(except);
        a:
        for (T a : S) {
            if (!unpaired.contains(a))
                continue;
            for (T b : S) {
                if (e.equals(eval(a, b)) && e.equals(eval(b, a))) {
                    unpaired.remove(a);
                    unpaired.remove(b);
                    continue a;
                }
            }
        }
        return unpaired.isEmpty();
    }
}

class Group<T> {
    final Set<T> S;
    final BinOp<T> op;
    final T identity;

    Group(BinOp<T> op) {
        this.S = op.getS();
        this.op = op;

        assertTrue("operator is not associative", op.associative());
        identity = op.identity();
        assertNotNull("has no identity element", identity);
        assertTrue("has elements without inverses", op.inverses(identity, null));
    }

    boolean abelian() {
        return op.commutative();
    }
}

class Ring<T> extends Group<T> {
    final BinOp<T> mulOp;
    final T unity;

    Ring(BinOp<T> addOp, BinOp<T> mulOp) {
        super(addOp);
        this.mulOp = mulOp;
        assertSame("operations defined over different sets", S, mulOp.getS());
        assertTrue("not abelian under addition", abelian());
        assertTrue("multiply operator is not associative", mulOp.associative());
        assertTrue("mul does not distribute over add", distributesOver(mulOp, op));
        unity = mulOp.identity();
    }

    boolean distributesOver(BinOp<T> op1, BinOp<T> op2) {
        System.err.println("Testing distributivity for " + getClass().getName());
        for (T a : S) {
            for (T b : S) {
                for (T c : S) {
                    T bplusc = op2.eval(b, c);
                    T ab = op1.eval(a, b);
                    T ac = op1.eval(a, c);
                    if (!op1.eval(a, bplusc).equals(op2.eval(ab, ac)))
                        return false;
                    T ba = op1.eval(b, a);
                    T ca = op1.eval(c, a);
                    if (!op1.eval(bplusc, a).equals(op2.eval(ba, ca)))
                        return false;
                }
            }
        }
        return true;
    }

    boolean commutative() {
        return mulOp.commutative();
    }

    boolean cancelation() {
        System.err.println("Testing cancelation for " + getClass().getName());
        for (T a : S) {
            if (identity.equals(a))
                continue;
            for (T b : S) {
                if (identity.equals(b))
                    continue;
                if (identity.equals(mulOp.eval(a, b)))
                    return false;
                // will also be checked for (b, a) in due course of loops
            }
        }
        return true;
    }

    boolean nonzerosInvertible() {
        return mulOp.inverses(unity, identity);
    }
}

class IntegralDomain<T> extends Ring<T> {
    IntegralDomain(BinOp<T> addOp, BinOp<T> mulOp) {
        super(addOp, mulOp);
        assertTrue("ring not commutative", commutative());
        assertNotNull("ring lacks unity", unity);
        assertTrue("ring lacks cancelation property", cancelation());
    }
}

class Field<T> extends IntegralDomain<T> {
    @Override
    boolean cancelation() {
        return true;
    } // implied by stricter test below

    Field(BinOp<T> addOp, BinOp<T> mulOp) {
        super(addOp, mulOp);
        assertTrue("not all nonzeros invertible", nonzerosInvertible());
    }
}
