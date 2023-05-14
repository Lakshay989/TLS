

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

    public class Server {
        // Static Member Variables
        private static int PORT = 8080;
        private static final String certificatePath = "./src/resources/CASignedServerCertificate.pem";
        private static final String privateKeyPath = "./src/resources/serverPrivateKey.der";


        // Member Variables
        private byte[] nonce;
        private Socket socket;
        private ServerSocket serverSocket;
        private Certificate signedServerCertificate;
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

        public Server() throws IOException, CertificateException, NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, InvalidKeyException {
            this.signedServerCertificate = Shared.getCertificate(certificatePath);
            this.dhPrivateKey = new BigInteger(Integer.toString(new SecureRandom().nextInt()));
            this.rsaPrivateKey = Shared.getRSAPrivateKey(privateKeyPath);
            this.dhPublicKey = Shared.getDHPublicKey(this.dhPrivateKey);
            this.signedDHPublicKey = Shared.getSignedKey(rsaPrivateKey, dhPublicKey);

            this.serverSocket = new ServerSocket(PORT);
//        this.socket = serverSocket.accept();
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

        public static void main(String[] args) throws CertificateException, IOException, NoSuchAlgorithmException,
                InvalidKeySpecException, SignatureException, InvalidKeyException, ClassNotFoundException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {

            // Initialise the server
            Server server = new Server();
            System.out.println("Server has been initialised.");

            while(true) {
                try {

                    // Wait for connection
                    server.socket = server.serverSocket.accept();
                    System.out.println("Connection with a client has been established.");

                    // Initialise I/O streams
                    ObjectOutputStream outputStream = new ObjectOutputStream(server.socket.getOutputStream());
                    ObjectInputStream inputStream = new ObjectInputStream(server.socket.getInputStream());

                    System.out.println("Initialising I/O streams.");

                    // Initialise byte stream for summary
                    ByteArrayOutputStream summary = new ByteArrayOutputStream();

                    // Handle nonce
                    System.out.println("Attempting to start handshake...");
                    server.nonce = (byte[]) inputStream.readObject();
                    summary.write(server.nonce);

                    // Send server certificate, DH public key, signed DH public key
                    outputStream.flush();
                    outputStream.writeObject(server.signedServerCertificate);
                    outputStream.writeObject(server.dhPublicKey);
                    outputStream.writeObject(server.signedDHPublicKey);
                    summary.write(server.signedServerCertificate.getEncoded());
                    summary.write(server.dhPublicKey.toByteArray());
                    summary.write(server.signedDHPublicKey);

                    // Receive client certificate, DH public key, signed DH public key
                    Certificate clientCertificate;
                    BigInteger clientDHPublicKey;
                    byte[] clientSignedDHPublicKey;

                    clientCertificate = (Certificate) inputStream.readObject();
                    clientDHPublicKey = (BigInteger) inputStream.readObject();
                    clientSignedDHPublicKey = (byte[]) inputStream.readObject();

                    summary.write(clientCertificate.getEncoded());
                    summary.write(clientDHPublicKey.toByteArray());
                    summary.write(clientSignedDHPublicKey);

                    // Verify client
                    if (!Shared.verifyHost(clientCertificate, clientDHPublicKey, clientSignedDHPublicKey)) {
                        System.out.println("Client was not verified, program will move on to the next request.");
                        continue;
                    }
                    System.out.println("Client has been verified.");

                    // Calculate shared secret
                    BigInteger secret = Shared.getDHSharedSecret(clientDHPublicKey, server.dhPrivateKey);
                    System.out.println("Calculated the shared secret.");

                    // Generate MAC
                    server.makeSecretKeys(server.nonce, secret.toByteArray());
                    System.out.println("Generated MACs.");

                    // Respond with summary and server MAC
                    byte[] message = Shared.prepareMessage(summary.toByteArray(), server.serverMAC);
                    outputStream.writeObject(message);
                    summary.write(message);

                    // Record client summary and compare
                    byte[] clientSummary = (byte[]) inputStream.readObject();
                    byte[] serverSummary = Shared.prepareMessage(summary.toByteArray(), server.clientMAC);

                    if (!Arrays.equals(clientSummary, serverSummary)) {
                        System.out.println("Invalid response from the client, the summary doesn't match. Please try again.");
                        continue;
                    }
                    System.out.println("Handshake complete.");
                    System.out.println("\n\n");

//-----------------------------------------------------------------------------------------------------------------

                    System.out.println("Sending test messages to the Client ...");
                    //Prepare message to send

                    String server_test_message1 = "Test Message 1 from Server" ;

                    byte [] message1B = server_test_message1.getBytes();
                    byte[] hashedMessageBytes1 = Shared.prepareMessage(message1B, server.serverEncrypt);
                    byte[] concatBytes1 = Shared.concatenate(message1B, hashedMessageBytes1);

                    // Encrypt data
                    //System.out.println("Encrypting message.");
                    Cipher cipher1 = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    cipher1.init(Cipher.ENCRYPT_MODE, server.serverEncrypt, server.serverIV);
                    byte[] encryptedBytes1 = cipher1.doFinal(concatBytes1);
                    outputStream.writeObject(encryptedBytes1);
                    System.out.println("Sent message1 to client.");

 // ------------------------------------------------------------------------------------------------------------
                    String server_test_message2 = "Test Message 2 from Server" ;

                    byte [] message2B = server_test_message2.getBytes();
                    byte[] hashedMessageBytes2 = Shared.prepareMessage(message2B, server.serverEncrypt);
                    byte[] concatBytes2 = Shared.concatenate(message2B, hashedMessageBytes2);

                    // Encrypt data
                    //System.out.println("Encrypting message.");
                    Cipher cipher2 = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    cipher2.init(Cipher.ENCRYPT_MODE, server.serverEncrypt, server.serverIV);
                    byte[] encryptedBytes = cipher2.doFinal(concatBytes2);
                    outputStream.writeObject(encryptedBytes);
                    System.out.println("Sent message2 to client.");

// ------------------------------------------------------------------------------------------------------------

                    // Receiving Acknowledgement from the client

                    byte[] encryptedData = (byte[]) inputStream.readObject();
                    Cipher cipher3 = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    cipher3.init(Cipher.DECRYPT_MODE, server.clientEncrypt, server.clientIV);
                    byte[] decryptedData = cipher3.doFinal(encryptedData);


                    byte[] originalMessage = Arrays.copyOfRange(decryptedData, 0, decryptedData.length - 32);
                    byte[] MAC = Arrays.copyOfRange(decryptedData, decryptedData.length - 32, decryptedData.length);

                    byte[] calculatedMAC = Shared.prepareMessage(originalMessage, server.clientEncrypt);
                    if (Arrays.equals(calculatedMAC, MAC)) {
                        // The message is authentic
                        String receivedMessage = new String(originalMessage);
                        System.out.println(receivedMessage + "\n");
                    } else {
                        // The message has been tampered with
                        System.err.println("The received message has been tampered with!");
                    }

                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
    }