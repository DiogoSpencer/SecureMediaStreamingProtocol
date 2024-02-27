package security;

import security.cryptography.MessageFactory;
import security.cryptography.exceptions.CryptoException;
import security.cryptography.exceptions.WrongDigestException;


import java.io.IOException;
import java.net.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class mySimplifiedSRTSPDatagramSockets extends DatagramSocket {

    private DatagramPacket currentPacket;
    private getConfigs configs;

    public mySimplifiedSRTSPDatagramSockets(getConfigs configs) throws SocketException {
        super();
        currentPacket = null;
        this.configs = configs;
    }

    public mySimplifiedSRTSPDatagramSockets(SocketAddress socketAddress, getConfigs configs) throws SocketException {
        super(socketAddress);
        currentPacket = null;
        this.configs = configs;
    }

    /**
     * Receives a non encrypted packet, encrypts its contents and stores
     * its value for later sending
     *
     * @param p - non encrypted packet
     */
    public void preparePacket(DatagramPacket p)
            throws NoSuchAlgorithmException, InvalidKeyException, CryptoException {

        byte[] message = new byte[p.getLength()];
        System.arraycopy(p.getData(), 0, message, 0, p.getLength());

        byte[] protectedData = MessageFactory.buildProtectedMessage(message, configs);

        byte[] pdata = p.getData();
        System.arraycopy(protectedData, 0, pdata, 0, protectedData.length);
        p.setData(pdata);
        p.setLength(protectedData.length);

        currentPacket = p;
    }

    /**
     * Sends the already encrypted packet
     * @throws IOException
     */
    public void send() throws IOException {

        super.send(currentPacket);
    }

    /**
     *
     *
     */
    public void mySSPReceive(DatagramPacket p) throws InvalidKeyException, NoSuchAlgorithmException,
            CryptoException, WrongDigestException, IOException {

        super.receive(p);


        byte[] protectedMessage = new byte[p.getLength()];

        System.arraycopy(p.getData(), 0, protectedMessage, 0, p.getLength());

        byte[] message = MessageFactory.decipherProtectedMessage(protectedMessage, configs);

        byte[] data = p.getData();
        System.arraycopy(message, 0, data, 0, message.length);

        p.setData(data);
        p.setLength(message.length);

        //
    }

}