package security.cryptography;

import security.cryptography.exceptions.CryptoException;

import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class Cryptography {


    public static byte[] crypt(byte[] inputBytes, byte[] key, String algorithm,
                                String transformation, byte[] ivBytes) throws CryptoException {

        return doCrypto(Cipher.ENCRYPT_MODE, key, inputBytes, algorithm, transformation, ivBytes);
    }


    public static byte[] decrypt(byte[] inputBytes, byte[] key, String algorithm,
                                 String transformation, byte[] ivBytes) throws CryptoException {

        return doCrypto(Cipher.DECRYPT_MODE, key, inputBytes, algorithm, transformation, ivBytes);
    }


    private static byte[] doCrypto(int cipherMode, byte[] key, byte[] inputBytes, String algorithm,
                                   String transformation, byte[] ivBytes) throws CryptoException {

        try {
            /*
            byte[] ivBytes = new byte[]{
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            };
             */

            IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
            Key secretKey = new SecretKeySpec(key, algorithm);
            Cipher cipher = Cipher.getInstance(transformation);
            cipher.init(cipherMode, secretKey, ivSpec);

            return cipher.doFinal(inputBytes);

        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | BadPaddingException |
                IllegalBlockSizeException | InvalidAlgorithmParameterException ex) {
            throw new CryptoException("Error encrypting/decrypting file", ex);
        }

    }

    public static byte[] digest(String algorithm, byte[] key, byte[] message)
            throws NoSuchAlgorithmException, InvalidKeyException {

        Mac hMac = Mac.getInstance(algorithm);
        Key key2 = new SecretKeySpec(key, algorithm);
        hMac.init(key2);

        return hMac.doFinal(message);
    }

    public static int digestLength(String algorithm, byte[] key)
            throws NoSuchAlgorithmException, InvalidKeyException {

        Mac hMac = Mac.getInstance(algorithm);
        Key key2 = new SecretKeySpec(key, algorithm);
        hMac.init(key2);

        return hMac.getMacLength();
    }

}
