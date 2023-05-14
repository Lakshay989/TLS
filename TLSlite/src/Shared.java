
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

    public class Shared {
        // https://www.ietf.org/rfc/rfc3526.txt, page 4
        private static final BigInteger GENERATOR = new BigInteger("2");
        private static final BigInteger PRIME = new BigInteger("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF", 16);
        private static final String CaCertificatePath = "./src/resources/CAcertificate.pem";

        public static Certificate getCertificate(String filename) throws CertificateException, FileNotFoundException {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            InputStream file = new FileInputStream(filename);
            return certificateFactory.generateCertificate(file);
        }

        public static PrivateKey getRSAPrivateKey(String filename) throws IOException, NoSuchAlgorithmException,
                InvalidKeySpecException {
            InputStream file = new FileInputStream(filename);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(file.readAllBytes());
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePrivate(keySpec);
        }

        public static BigInteger getDHPublicKey(BigInteger dhPrivateKey) {
            return GENERATOR.modPow(dhPrivateKey, PRIME);
        }

        public static byte[] getSignedKey(PrivateKey rsaPrivateKey, BigInteger dhPublicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
            Signature signature = Signature.getInstance("SHA256WithRSA");
            signature.initSign(rsaPrivateKey);
            signature.update(dhPublicKey.toByteArray());
            return signature.sign();
        }

        public static byte[] hdkfExpand(byte[] input, String tag) throws NoSuchAlgorithmException, InvalidKeyException {
            byte[] tagArr = new byte[tag.getBytes().length + 1];
            byte[] temp = tag.getBytes();
            System.arraycopy(temp, 0, tagArr, 0, tagArr.length - 1);
            tagArr[tagArr.length - 1] = 1;

            final Mac HMAC = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKeySpec = new SecretKeySpec(input, "HmacSHA256");
            HMAC.init(secretKeySpec);

            byte[] okm = HMAC.doFinal(tagArr);
            byte[] out = new byte[16];
            System.arraycopy(okm, 0, out, 0, out.length);

            return out;
        }

        public static boolean verifyCertificate(Certificate certificate) throws FileNotFoundException, CertificateException {
            Certificate CaCertificate = getCertificate(CaCertificatePath);
            try {
                certificate.verify(CaCertificate.getPublicKey());
                return true;
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (InvalidKeyException e) {
                e.printStackTrace();
            } catch (NoSuchProviderException e) {
                e.printStackTrace();
            } catch (SignatureException e) {
                e.printStackTrace();
            } catch (Exception e) {
                e.printStackTrace();
            }
            return false;
        }

        public static boolean verifyHost(Certificate clientCert, BigInteger clientDHPublicKey,
                                         byte[] clientSignedDHPublicKey) throws FileNotFoundException,
                CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
            if (!verifyCertificate(clientCert)) { // Verify client certificate with CA certificate.
                System.out.println("Failed to verify certificate.");
                return false;
            }

            Signature signature = Signature.getInstance("SHA256WithRSA");
            signature.initVerify(clientCert);
            signature.update(clientDHPublicKey.toByteArray());

            return signature.verify(clientSignedDHPublicKey);
        }

        public static BigInteger getDHSharedSecret(BigInteger DHKey, BigInteger privateKey) {
            return DHKey.modPow(privateKey, PRIME);
        }

        public static byte[] prepareMessage(byte[] message, SecretKeySpec MAC) throws NoSuchAlgorithmException,
                InvalidKeyException {
            Mac HMAC = Mac.getInstance("HmacSHA256");
            HMAC.init(MAC);
            return HMAC.doFinal(message);
        }

        public static byte[] concatenate(byte[] byteArray1, byte[] byteArray2) {
            int n = byteArray1.length + byteArray2.length;
            byte[] temp = new byte[n];
            for (int i = 0; i < n; i++) {
                if (i < byteArray1.length) {
                    temp[i] = byteArray1[i];
                } else {
                    temp[i] = byteArray2[i - byteArray1.length];
                }
            }
            return temp;
        }

        public static byte[] getNonceObject() {
            byte[] nonce = new byte[32];
            new SecureRandom().nextBytes(nonce);
            return nonce;
        }

//        public  static byte[] encryptMessage( String message_to_be_sent)
//        {
//            byte [] messageInBytes = message_to_be_sent.getBytes();
//            byte[] hashedMessageBytes = Helper.prepareMessage(message1B, server.serverEncrypt);
//            byte[] concatBytes = Helper.concatenate(messageInBytes, hashedMessageBytes);
//
//            // Encrypt data
//            //System.out.println("Encrypting message.");
//            Cipher cipher1 = Cipher.getInstance("AES/CBC/PKCS5Padding");
//            cipher1.init(Cipher.ENCRYPT_MODE, server.serverEncrypt, server.serverIV);
//            byte[] encryptedBytes1 = cipher1.doFinal(concatBytes1);
//            outputStream.writeObject(encryptedBytes1);
//            System.out.println("Sent message1 to client.");
//        }

    }
