package Client;

import java.math.BigInteger;
import java.security.SignatureException;
import java.sql.DataTruncation;

/**
 * Created by bezru on 21.02.2017.
 */
public class SignatureDecode {

    public boolean aBoolean;

    public SignatureDecode(BigInteger q, BigInteger g, BigInteger p, BigInteger publicKey,
                           BigInteger hash, BigInteger[] sign) throws SignatureException {
        checkSignature(q, g, p, publicKey, hash, sign);
    }

    private void checkSignature(BigInteger q, BigInteger g, BigInteger p, BigInteger publicKey,
                                BigInteger hash, BigInteger[] sign) throws SignatureException {
        BigInteger r = sign[0];
        BigInteger s = sign[1];
        //проверка подписи на валидность (оба значения должны быть положительными)
        if (r.signum() < 0) {
            r = new BigInteger(1, r.toByteArray());
        }
        if (s.signum() < 0) {
            s = new BigInteger(1, s.toByteArray());
        }
        if ((r.compareTo(q) == -1) && (s.compareTo(q) == -1)) {
            BigInteger w = generateW(q, s);
            System.out.println(w.toString());
            BigInteger v = generateV(publicKey, p, q, g, w, r, hash);
            System.out.println(v.toString());
            System.out.println(r.toString());
            aBoolean = v.equals(r);
        } else {
            throw new SignatureException("Invalid signature");
        }
    }

    private BigInteger generateW(BigInteger q, BigInteger s) {
        return s.modInverse(q);
    }

    private BigInteger generateV(BigInteger publicKey, BigInteger p, BigInteger q, BigInteger g, BigInteger w, BigInteger r, BigInteger hash) {
        byte[] hashBytes = hash.toByteArray();
        BigInteger hashInteger = new BigInteger(1, hashBytes);
        hashInteger = hashInteger.multiply(w);
        BigInteger u1 = hashInteger.remainder(q);
        BigInteger u2 = (r.multiply(w)).remainder(q);
        BigInteger t1 = g.modPow(u1, p);
        BigInteger t2 = publicKey.modPow(u2, p);
        BigInteger t3 = t1.multiply(t2);
        BigInteger t4 = t3.remainder(p);

        return t4.remainder(q);
    }
}
