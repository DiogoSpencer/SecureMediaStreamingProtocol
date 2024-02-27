package security;

import utils.Utils;
import java.util.Properties;


public class getConfigs {

    private final String cryptoCiphersuite;
    private final String macCiphersuite;
    private final byte[] iv;
    private final byte[] sessionKeySize;
    private final byte[] sessionKey;
    private final byte[] macKey;
    


    public getConfigs(Properties SSPProperties){
        cryptoCiphersuite   = SSPProperties.getProperty("CRYPTOCS");
        macCiphersuite      = SSPProperties.getProperty("MACCS");
        iv                  = Utils.hexaStringToByteArray(SSPProperties.getProperty("IV"));
        sessionKeySize      = SSPProperties.getProperty("CKEYSIZE").getBytes();
        sessionKey          = Utils.hexaStringToByteArray(SSPProperties.getProperty("CKEY"));
        macKey              = Utils.hexaStringToByteArray(SSPProperties.getProperty("MACKEY"));
    }



    public String getCryptoCiphersuite() {
        return cryptoCiphersuite;
    }

    public String getMacCiphersuite() {
        return macCiphersuite;
    }


    public byte[] getIv() {
        return iv;
    }

    public byte[] getSessionKeySize() {
        return sessionKeySize;
    }

    public byte[] getSessionKey() {
        return sessionKey;
    }


    public byte[] getMacKey() {
        return macKey;
    }

}
