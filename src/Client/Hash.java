package Client;

// import org.apache.log4j.Logger;

import java.io.*;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

/**
 * Created by dorn on 11.02.2017.
 */

public class Hash {
    //final static Logger log = Logger.getLogger(Decoder.class);
    protected static BigInteger getHash (File file) {
        //log.info("End initialization array");
        try {
            FileInputStream input = new FileInputStream(file);
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] buffer = new byte[1024];
            int readed = 0;
            while ((readed = input.read(buffer)) != -1) {
                md.update(buffer, 0, readed);
            }
            byte[] hashCode = md.digest();
            return new BigInteger(1, hashCode);
        }
        catch(Exception e){
            e.printStackTrace();
        }
        return null;
    }
}
