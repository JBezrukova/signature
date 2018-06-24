package Client;

import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.SignatureException;

/**
 * Created by bezru on 08.02.2017.
 */


public class Decoder implements Serializable {


    public boolean start(Packet packet) throws SignatureException {

        BigInteger q = packet.q;
        BigInteger g = packet.g;
        BigInteger p = packet.p;
        File file = packet.file;
        BigInteger publicKey = packet.publicKey;
        BigInteger[] sign = packet.sign;
        BigInteger hash = null;
        hash = Hash.getHash(file);
        SignatureDecode decode = new SignatureDecode(q, g, p, publicKey, hash, sign);
        System.out.println(decode.aBoolean);
        return decode.aBoolean;
    }

}

