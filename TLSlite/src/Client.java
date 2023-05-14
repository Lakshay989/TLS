
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

public class Client {
    // Static Member Variables
    private static int PORT = 8080;
    private static final String certificatePath = "./src/resources/CASignedClientCertificate.pem";
    private static final String privateKeyPath = "./src/resources/clientPrivateKey.der";

    // Member Variables
    private byte[] nonce;
    private Socket socket;
    private Certificate signedClientCertificate;
    private PrivateKey rsaPrivateKey;
    private BigInteger dhPublicKey;
    private BigInteger dhPrivateKey;
    private byte[] signedDHPublicKey;

    // Keys
    private SecretKeySpec serverEncrypt;
    private SecretKeySpec clientEncrypt;
    private SecretKeySpec serverMAC;
    private SecretKeySpec clientMAC;
    private IvParameterSpec serverIV;
    private IvParameterSpec clientIV;

    public Client() throws IOException, CertificateException, NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, InvalidKeyException {
        this.nonce = Shared.getNonceObject();
        this.signedClientCertificate = Shared.getCertificate(certificatePath);
        this.rsaPrivateKey = Shared.getRSAPrivateKey(privateKeyPath);
        this.dhPrivateKey = new BigInteger(Integer.toString(new SecureRandom().nextInt()));
        this.dhPublicKey = Shared.getDHPublicKey(this.dhPrivateKey);
        this.signedDHPublicKey = Shared.getSignedKey(this.rsaPrivateKey, this.dhPublicKey);
        this.socket = new Socket("127.0.0.1", PORT);
    }

    public void makeSecretKeys(byte[] nonce, byte[] sharedSecretKey) throws NoSuchAlgorithmException,
            InvalidKeyException {
        final Mac HMAC = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(this.nonce, "HmacSHA256");
        HMAC.init(secretKeySpec);
        byte[] prk = HMAC.doFinal(sharedSecretKey);
        serverEncrypt = new SecretKeySpec(Shared.hdkfExpand(prk, "server encrypt"), "AES");
        clientEncrypt = new SecretKeySpec(Shared.hdkfExpand(serverEncrypt.getEncoded(), "client encrypt"), "AES");
        serverMAC = new SecretKeySpec(Shared.hdkfExpand(clientEncrypt.getEncoded(), "server MAC"), "AES");
        clientMAC = new SecretKeySpec(Shared.hdkfExpand(serverMAC.getEncoded(), "client MAC"), "AES");
        serverIV = new IvParameterSpec(Shared.hdkfExpand(clientMAC.getEncoded(), "server IV"));
        clientIV = new IvParameterSpec(Shared.hdkfExpand(serverIV.getIV(), "client IV"));
    }

    public static void main(String[] args) {
        try {
            // Initialise client
            System.out.println("Initializing client...");
            Client client = new Client();
            System.out.println("Done.");

            // Setup I/O streams
            System.out.println("Setting up I/O streams and summary...");
            ObjectInputStream inputStream = new ObjectInputStream(client.socket.getInputStream());
            ObjectOutputStream outputStream = new ObjectOutputStream(client.socket.getOutputStream());
            ByteArrayOutputStream summary = new ByteArrayOutputStream();
            System.out.println("Done.");

            // Send Nonce
            outputStream.flush();
            outputStream.writeObject(client.nonce);
            summary.write(client.nonce);

            // Receive server certificate, DH public key, signed DH public key
            Certificate serverCertificate;
            BigInteger serverDHPublicKey;
            byte[] serverSignedDHPublicKey;

            serverCertificate = (Certificate) inputStream.readObject();
            serverDHPublicKey = (BigInteger) inputStream.readObject();
            serverSignedDHPublicKey = (byte[]) inputStream.readObject();

            summary.write(serverCertificate.getEncoded());
            summary.write(serverDHPublicKey.toByteArray());
            summary.write(serverSignedDHPublicKey);

            // Send client certificate, DH public key, signed DH public key
            outputStream.writeObject(client.signedClientCertificate);
            outputStream.writeObject(client.dhPublicKey);
            outputStream.writeObject(client.signedDHPublicKey);
            summary.write(client.signedClientCertificate.getEncoded());
            summary.write(client.dhPublicKey.toByteArray());
            summary.write(client.signedDHPublicKey);

            // Verify Server
            if(!Shared.verifyHost(serverCertificate, serverDHPublicKey, serverSignedDHPublicKey)) {
                System.out.println("Server was not verified, program will stop. Re-run client to try again.");
                System.exit(1);
            } else {
                System.out.println("Host has been verified.");
            }

            // Calculate shared secret
            BigInteger secret = Shared.getDHSharedSecret(serverDHPublicKey, client.dhPrivateKey);
            System.out.println("Calculated the shared secret.");

            // Get MAC Keys
            client.makeSecretKeys(client.nonce, secret.toByteArray());
            System.out.println("Generated MACs.");

            // Receive server summary and MAC and compare
            byte[] serverSummary = (byte[]) inputStream.readObject();
            byte[] clientSummary = Shared.prepareMessage(summary.toByteArray(), client.serverMAC);

            if (!Arrays.equals(clientSummary, serverSummary)) {
                System.out.println("Invalid response from the server, the summary doesn't match. Please try again.");
                System.exit(1);
            } else {
                System.out.println("Summary matched.");
            }

            // Send updated summary to server
            summary.write(serverSummary);
            byte[] message = Shared.prepareMessage(summary.toByteArray(), client.clientMAC);
            outputStream.writeObject(message);


            System.out.println("Handshake complete.");
            System.out.println("\n");
//---------------------------------------------------------------------------------------------------------------

            System.out.println("Waiting for the messages from the Server... \n");

            //String receviedMessage = (String) inputStream.readObject() ;
            //System.out.println("Received the following message : \n");

            byte[] encryptedData = (byte[]) inputStream.readObject();
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, client.serverEncrypt, client.serverIV);
            byte[] decryptedData = cipher.doFinal(encryptedData);


            byte[] originalMessage = Arrays.copyOfRange(decryptedData, 0, decryptedData.length - 32);
            byte[] MAC = Arrays.copyOfRange(decryptedData, decryptedData.length - 32, decryptedData.length);

            byte[] calculatedMAC = Shared.prepareMessage(originalMessage, client.serverEncrypt);
            if (Arrays.equals(calculatedMAC, MAC)) {
                // The message is authentic
                String receivedMessage = new String(originalMessage);
                System.out.println(receivedMessage);
            } else {
                // The message has been tampered with
                System.err.println("The received message has been tampered with!");
            }


//            String receviedMessage = new String(MAC) ;
//            System.out.println(receviedMessage);
            //System.out.println("Done.");

//--------------------------------------------------------------------------------------------
            byte[] encryptedData2 = (byte[]) inputStream.readObject();
            Cipher cipher2 = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, client.serverEncrypt, client.serverIV);
            byte[] decryptedData2 = cipher.doFinal(encryptedData2);


            byte[] originalMessage2 = Arrays.copyOfRange(decryptedData2, 0, decryptedData2.length - 32);
            byte[] MAC2 = Arrays.copyOfRange(decryptedData2, decryptedData2.length - 32, decryptedData2.length);

            byte[] calculatedMAC2 = Shared.prepareMessage(originalMessage2, client.serverEncrypt);
            if (Arrays.equals(calculatedMAC2, MAC2)) {
                // The message is authentic
                String receivedMessage = new String(originalMessage2);
                System.out.println(receivedMessage + "\n");
            } else {
                // The message has been tampered with
                System.err.println("The received message has been tampered with!");
            }
//--------------------------------------------------------------------------------------------
            String client_acknowledgement_message = "Acknowledgement message from the client received" ;

            byte [] message_ack_B = client_acknowledgement_message.getBytes();
            byte[] hashedAckMessageBytes = Shared.prepareMessage(message_ack_B, client.clientEncrypt);
            byte[] concatBytes = Shared.concatenate(message_ack_B, hashedAckMessageBytes);

            // Encrypt data
            //System.out.println("Encrypting message.");
            Cipher cipher3 = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher2.init(Cipher.ENCRYPT_MODE, client.clientEncrypt, client.clientIV);
            byte[] encryptedBytes = cipher2.doFinal(concatBytes);
            outputStream.writeObject(encryptedBytes);
            System.out.println("Sent acknowledgement to server.");
        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }

}
