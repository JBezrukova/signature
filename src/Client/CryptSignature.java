package Client;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;


import static java.math.BigInteger.ONE;


/**
 * Created by bezru on 21.02.2017.
 */
public class CryptSignature {
    private BigInteger q;
    private BigInteger p;
    private BigInteger g;
    private BigInteger secretKey;
    private BigInteger publicKey;
    private BigInteger k;
    private BigInteger hash;


    public CryptSignature(BigInteger hash) {
        this.hash = hash;
        generatePandQ(new SecureRandom(), 1024);
        //System.out.println("P: " + p + "Q: " + q);
        //generate();
        //generateQ();
        generateK();
        // generateP();
        generateG();
        generateSecretKey();
        generatePublicKey();
    }

    private void generatePandQ(SecureRandom random, int L) {
        double startTime = System.nanoTime();
        BigInteger[] result = null;
        byte[] seed = new byte[20];

        while (result == null) {
            for (int i = 0; i < 20; i++) {
                seed[i] = (byte) random.nextInt();
            }
            result = generatePandQ(seed, L);
        }
        p = result[0];
        q = result[1];
        double timeSpent = (System.nanoTime() - startTime) / 1000000;
        NewJFrame.getInstance().setQTime(timeSpent);
        NewJFrame.getInstance().setPTime(timeSpent);
    }

    public BigInteger[] sign() {
        BigInteger[] sign = new BigInteger[2];
        sign[0] = generateR();
        sign[1] = generateS(sign[0]);
        return sign;
    }

    private BigInteger generateS(BigInteger r) {
        double startTime = System.nanoTime();
        byte[] hashBytes = hash.toByteArray();
        BigInteger hashInteger = new BigInteger(1, hashBytes);
        BigInteger kInversed = k.modInverse(q);

        BigInteger s = secretKey.multiply(r);
        s = hashInteger.add(s);
        s = kInversed.multiply(s);
        s = s.remainder(q);
        double timeSpent = (System.nanoTime() - startTime) / 1000000;
        NewJFrame.getInstance().setSTime(timeSpent);
        return s;
    }

    private BigInteger generateR() {
        double startTime = System.nanoTime();
        BigInteger r = g.modPow(k, p);
        r = r.remainder(q);
        double timeSpent = (System.nanoTime() - startTime) / 1000000;
        NewJFrame.getInstance().setRTime(timeSpent);
        return r;
    }

    private void generateSecretKey() {
        secretKey = new BigInteger(1024, new Random());
        //secretKey =  new BigInteger("35220391005816087854789561601934045441234714150080737342897134685461929030750666777603177461516648480002220589542215028682945798220980297844365283306145740982917478954696489400138350815145177832185394407777644860505118077715674071059239867646656446667960824181854775080132764956238894286214515664256101369582");
        System.out.println("secret key " + secretKey);
    }

    private void generatePublicKey() {
        double startTime = System.nanoTime();
        publicKey = g.modPow(secretKey, p);
        double timeSpent = (System.nanoTime() - startTime) / 1000000;
        NewJFrame.getInstance().setKeyTime(timeSpent);
    }

    //(0,q)
    private void generateK() {
        k = new BigInteger(128, new Random());
    }

    public BigInteger getQ() {
        return q;
    }

    public BigInteger getP() {
        return p;
    }

    public BigInteger getG() {
        return g;
    }

    public BigInteger getSecretKey() {
        return secretKey;
    }

    public BigInteger getPublicKey() {
        return publicKey;
    }

    public BigInteger getR() {
        return sign()[0];
    }

    public BigInteger getS() {
        return sign()[1];
    }

    private void generateG() {
        double startTime = System.nanoTime();
        BigInteger TWO = BigInteger.valueOf(2);
        BigInteger h = ONE;
        BigInteger pMinusOneOverQ = (p.subtract(ONE)).divide(q);
        g = ONE;
        while (g.compareTo(TWO) < 0) {
            g = h.modPow(pMinusOneOverQ, p);
            h = h.add(ONE);
        }
        double timeSpent = (System.nanoTime() - startTime) / 1000000;
        NewJFrame.getInstance().setGTime(timeSpent);
    }

    private BigInteger[] generatePandQ(byte[] seed, int L) {
        int g = (seed.length * 8);
        int n = (L - 1) / 160;
        int b = (L - 1) % 160;
        BigInteger TWO = BigInteger.valueOf(2);

        BigInteger SEED = new BigInteger(1, seed);
        BigInteger TWOG = BigInteger.valueOf(2).pow(2 * g);

        byte[] U1 = hashFunction(seed);
        byte[] U2 = hashFunction(((SEED.add(ONE)).mod(TWOG)).toByteArray());

        xor(U1, U2);
        byte[] U = U1;

        U[0] |= 0x80;
        U[19] |= 1;
        BigInteger q = new BigInteger(1, U);


        if (!q.isProbablePrime(80)) {
            return null;

        } else {
            BigInteger V[] = new BigInteger[n + 1];
            BigInteger offset = BigInteger.valueOf(2);


            for (int counter = 0; counter < 4096; counter++) {


                for (int k = 0; k <= n; k++) {
                    BigInteger K = BigInteger.valueOf(k);
                    BigInteger tmp = (SEED.add(offset).add(K)).mod(TWOG);
                    V[k] = new BigInteger(1, hashFunction((tmp).toByteArray()));
                }


                BigInteger W = V[0];
                for (int i = 1; i < n; i++) {
                    W = W.add(V[i].multiply(TWO.pow(i * 160)));
                }
                W = W.add((V[n].mod(TWO.pow(b))).multiply(TWO.pow(n * 160)));

                BigInteger TWOLm1 = TWO.pow(L - 1);
                BigInteger X = W.add(TWOLm1);


                BigInteger c = X.mod(q.multiply(TWO));
                BigInteger p = X.subtract(c.subtract(ONE));


                if (p.compareTo(TWOLm1) > -1 && p.isProbablePrime(80)) {
                    BigInteger[] result = {p, q, SEED,
                            BigInteger.valueOf(counter)};
                    return result;
                }
                offset = offset.add(BigInteger.valueOf(n)).add(ONE);
            }
            return null;
        }
    }

    private boolean checkIfPrime(BigInteger value) {
        long i = 2;
        long j = 0;
        while (value.compareTo(BigInteger.valueOf((long) Math.pow(i, i))) > -1 && j != 1) {
            if (value.mod(BigInteger.valueOf(i)).compareTo(BigInteger.ZERO) == 0) {
                j = 1;
            } else {
                i = i + 1;
            }
        }
        if (j == 1) {
            System.out.println("FALSE");
            return false;
        } else {
            return true;
        }
    }

    private BigInteger hashFunction(BigInteger s) {
        byte hash[] = null;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(s.toByteArray());
            hash = md.digest();
        } catch (Exception e) {
            e.printStackTrace();
        }

        return new BigInteger(1, hash);
    }

    private byte[] hashFunction(byte[] s) {
        byte hash[] = null;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(s);
            hash = md.digest();
        } catch (Exception e) {
            e.printStackTrace();
        }

        return hash;
    }

    private void xor(byte[] U1, byte[] U2) {
        for (int i = 0; i < U1.length; i++) {
            U1[i] ^= U2[i];
        }
    }
}
