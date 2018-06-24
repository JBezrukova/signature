package Client;

import java.io.File;
import java.io.Serializable;
import java.math.BigInteger;

/**
 * Created by bezru on 14.06.2018.
 */
public class Packet implements Serializable {
    public String name;
    public File file;
    public long fileLen;
    public BigInteger q;
    public BigInteger p;
    public BigInteger g;
    public BigInteger publicKey;
    public BigInteger[] sign;
}
