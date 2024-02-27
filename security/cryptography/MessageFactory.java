package security.cryptography;

import security.getConfigs;
import security.cryptography.exceptions.*;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * This class generates the necessary messages for the SSProtocol
 */
public class MessageFactory {

    
    private static byte VERSIONCONTENT_TYPE = (byte) 0x10;
    private static int HEADER_SIZE = 3;
    




    public static byte[] buildProtectedMessage(byte[] data, getConfigs configs)
            throws CryptoException, NoSuchAlgorithmException, InvalidKeyException {


        //SRTSP-PAYLOAD

        

        byte[] frame = new byte[data.length];
        System.arraycopy(data, 0, frame, 0, data.length);

    

        String algorithm = configs.getCryptoCiphersuite().split("/")[0];
        byte[] encrypted = Cryptography.crypt(frame, configs.getSessionKey(), algorithm, configs.getCryptoCiphersuite(), configs.getIv());

        byte[] MpDigest = Cryptography.digest(configs.getMacCiphersuite(), configs.getMacKey(), encrypted);


        byte[] payload = new byte[ encrypted.length + MpDigest.length];
        System.arraycopy(encrypted, 0, payload, 0, encrypted.length);
        System.arraycopy(MpDigest, 0, payload, encrypted.length, MpDigest.length); 


        // SSRTSP-HEADER


        
            // returns byte array of size 2, holds size of message in ints
    
                    short num = (short)payload.length;
                    ByteBuffer dbuf = ByteBuffer.allocate(2);
                    dbuf.putShort(num);
                    byte[] sizeOfPayloadInInteger = dbuf.array();
            

        byte[] header = new byte[HEADER_SIZE];
    
        header[0] = VERSIONCONTENT_TYPE;
        header[1] = sizeOfPayloadInInteger[0];
        header[2] = sizeOfPayloadInInteger[1];
        
        



        byte[] msg = new byte[payload.length + HEADER_SIZE];
        System.arraycopy(header, 0, msg, 0, HEADER_SIZE);
        System.arraycopy(payload, 0, msg, HEADER_SIZE, payload.length);

        return msg;
    }


    public static byte[] decipherProtectedMessage(byte[] protectedMessage, getConfigs configs)
            throws NoSuchAlgorithmException, WrongDigestException, InvalidKeyException, CryptoException {


        int mpDigLen = Cryptography.digestLength(configs.getMacCiphersuite(), configs.getMacKey());


        byte[] encrypted = new byte[protectedMessage.length - HEADER_SIZE - mpDigLen];
        System.arraycopy(protectedMessage, HEADER_SIZE, encrypted, 0, encrypted.length);

        byte[] mac = new byte[mpDigLen];
        System.arraycopy(protectedMessage, protectedMessage.length - mpDigLen, mac, 0, mac.length);



    

        byte[] expectedCDigest = Cryptography.digest(configs.getMacCiphersuite(), configs.getMacKey(), encrypted);

        if( !MessageDigest.isEqual(mac, expectedCDigest))
            throw new WrongDigestException();

        String algorithm = configs.getCryptoCiphersuite().split("/")[0];
        byte[] frame = Cryptography.decrypt(encrypted, configs.getSessionKey(), algorithm, configs.getCryptoCiphersuite(), configs.getIv());

        
        return frame;
    }
}
