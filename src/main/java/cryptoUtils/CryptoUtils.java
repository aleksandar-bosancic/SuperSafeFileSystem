package cryptoUtils;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import javax.crypto.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class CryptoUtils {
    private static final String NO_SUCH_ALGORITHM = "No such algorithm!";

    private CryptoUtils(){}

    public static String encryptPassword(String password, byte[] salt, int algorithmCode)  {
        String hashPassword = null;
        try {
            MessageDigest messageDigest;
            String algorithm;
            switch (algorithmCode){
                case 1 -> algorithm = "MD5";
                case 2 -> algorithm = "SHA-256";
                default -> algorithm = "SHA-512";
            }
            messageDigest = MessageDigest.getInstance(algorithm);
            messageDigest.update(salt);
            hashPassword = new String(messageDigest.digest(password.getBytes()), StandardCharsets.UTF_8);
        } catch (NoSuchAlgorithmException e) {
            System.out.println(NO_SUCH_ALGORITHM);
        }
        return hashPassword;
    }

    public static byte[] hashData(byte[] input){
        byte[] output;
        MessageDigest messageDigest;
        try {
            messageDigest = MessageDigest.getInstance("SHA-512");
        } catch (NoSuchAlgorithmException e) {
            System.out.println(NO_SUCH_ALGORITHM);
            return new byte[0];
        }
        output = messageDigest.digest(input);
        return output;
    }

    public static SecretKey generateKey(int algorithmCode){
        KeyGenerator keyGenerator;
        SecretKey key = null;
        String algorithm;
        switch (algorithmCode){
            case 1 -> algorithm = "DES";
            case 2 -> algorithm = "RC4";
            default -> algorithm = "AES";
        }
        try {
            keyGenerator = KeyGenerator.getInstance(algorithm);
            key = keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException e) {
            System.out.println(NO_SUCH_ALGORITHM);
        }
        return key;
    }

    public static byte[] symmetricEncrypt(byte[] input, int algorithmCode, SecretKey key) {
        byte[] output = null;
        Cipher cipher;
        try {
            String algorithm;
            switch (algorithmCode){
                case 1 -> algorithm = "DES";
                case 2 -> algorithm = "RC4";
                default -> algorithm = "AES";
            }
            cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            output = cipher.doFinal(input);
        } catch (NoSuchAlgorithmException | IllegalBlockSizeException | BadPaddingException | NoSuchPaddingException | InvalidKeyException e) {
            System.out.println("Wrong key");
        }
        return output;
    }

    public static byte[] symmetricDecrypt(byte[] input, int algorithmCode, SecretKey key){
        byte[] output;
        Cipher cipher;
        try {
            String algorithm;
            switch (algorithmCode){
                case 1 -> algorithm = "DES";
                case 2 -> algorithm = "RC4";
                default -> algorithm = "AES";
            }
            cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.DECRYPT_MODE, key);
            output = cipher.doFinal(input);
        } catch (NoSuchAlgorithmException | IllegalBlockSizeException | BadPaddingException | NoSuchPaddingException | InvalidKeyException e) {
            System.out.println("Wrong decryption key!");
            return "You have not authorization to open this file!".getBytes(StandardCharsets.UTF_8);
        }
        return output;
    }

    public static PublicKey readPublicKey(String keyName){
        File publicKeyFile = new File(Paths.get("").toAbsolutePath() + File.separator + "CA" + File.separator + "public" + File.separator + keyName + ".key");
        if(!publicKeyFile.exists()){
            System.out.println("Key does not exist!");
            return null;
        }
        PublicKey publicKey;
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PemReader pemReader;
            try (FileReader fileReader = new FileReader(publicKeyFile)) {
                pemReader = new PemReader(fileReader);
                PemObject pemObject = pemReader.readPemObject();
                EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(pemObject.getContent());
                publicKey = keyFactory.generatePublic(publicKeySpec);
            }
        } catch (InvalidKeySpecException | IOException | NoSuchAlgorithmException e) {
            System.out.println("Invalid key");
            return null;
        }
        return publicKey;
    }

    public static PrivateKey readPrivateKey(String keyName){
        File privateKeyFile = new File(Paths.get("").toAbsolutePath() + File.separator + "CA" + File.separator + "private" + File.separator + keyName + ".key");
        if(!privateKeyFile.exists()){
            System.out.println("Key does not exist!");
            return null;
        }
        PrivateKey privateKey;
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PemReader pemReader;
            try (FileReader fileReader = new FileReader(privateKeyFile)) {
                pemReader = new PemReader(fileReader);
                PemObject pemObject = pemReader.readPemObject();
                EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(pemObject.getContent());
                privateKey = keyFactory.generatePrivate(privateKeySpec);
            }
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
            System.out.println("Invalid key");
            return null;
        }
        return privateKey;
    }

    public static byte[] asymmetricEncrypt(byte[] input, String keyName){
        PublicKey publicKey = readPublicKey(keyName);
        if(publicKey == null){
            return new byte[0];
        }
        Cipher cipher;
        byte[] output = null;
        try {
            cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            output = cipher.doFinal(input);
        } catch (NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
        return output;
    }

    public static byte[] asymmetricDecrypt(byte[] input, String keyName){
        PrivateKey privateKey = readPrivateKey(keyName);
        if(privateKey == null){
            return new byte[0];
        }
        Cipher cipher;
        byte[] output = null;
        try {
            cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            output = cipher.doFinal(input);
        } catch (NoSuchPaddingException | InvalidKeyException | BadPaddingException | NoSuchAlgorithmException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return output;
    }

    public static X509Certificate getCertificate(String name){
        X509Certificate x509Certificate = null;
        String pathToCert = Paths.get("").toAbsolutePath() + File.separator + "CA" + File.separator + "certs" + File.separator + name + ".pem";
        try {
            try (FileInputStream fileInputStream = new FileInputStream(pathToCert)) {
                CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
                x509Certificate = (X509Certificate) certificateFactory.generateCertificate(fileInputStream);
            }
        } catch (IOException | CertificateException e) {
            e.printStackTrace();
        }
        return x509Certificate;
    }

    public static void generateCertificate(String name){
        try {
            ProcessBuilder builder = new ProcessBuilder(
                    "cmd.exe", "/c", "cd CA && .\\gencert.sh " + name);
            builder.redirectErrorStream(true);
            Process p = null;
            p = builder.start();
            BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line;
            while (true) {
                line = r.readLine();
                if (line == null) { break; }
                System.out.println(line);
            }
        } catch (IOException e) {
            System.out.println("Could not generate certificate!");
        }
    }

    public static X509CRL getCrl(String name){
        X509CRL crl = null;
        String pathToCrl = Paths.get("").toAbsolutePath() + File.separator + "CA" + File.separator + "crl" + File.separator + name + ".pem";
        try {
            try (FileInputStream fileInputStream = new FileInputStream(pathToCrl)){
                CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
                crl = (X509CRL) certificateFactory.generateCRL(fileInputStream);
            }
        }   catch (IOException | CertificateException | CRLException e) {
            System.out.println("Could not load CRL!");
        }
        return crl;
    }

    public static boolean checkCertificateValidity(String name){
        X509Certificate certificate = getCertificate(name);
        X509Certificate caCertificate = getCertificate("rootca");
        X509CRL crl = getCrl("list1");
        String regex = "CN=" + name;
        if(!certificate.getSubjectDN().getName().contains(regex)){
            System.out.println("Name does not match with certificate name!");
            return false;
        }
        try {
            certificate.verify(caCertificate.getPublicKey());
        } catch (CertificateException | SignatureException | NoSuchProviderException | InvalidKeyException | NoSuchAlgorithmException e) {
            System.out.println("Certificate is invalid!");
            return false;
        }
        if(crl.isRevoked(certificate)){
            System.out.println("Certificate has been revoked!");
            return false;
        }
        try {
            certificate.checkValidity(java.util.Calendar.getInstance().getTime());
        } catch (CertificateNotYetValidException | CertificateExpiredException e) {
            System.out.println("Certificate has expired!");
            return false;
        }
        return true;
    }

    public static byte[] signFile(byte[] input, String keyName){
        byte[] signatureData = null;
        try {
            Signature signature = Signature.getInstance("SHA1withRSA");
            signature.initSign(readPrivateKey(keyName));
            signature.update(input);
            signatureData = signature.sign();
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            System.out.println("Invalid key!");
        }
        return signatureData;
    }

    public static boolean verifySignature(byte[] input, byte[] signatureBytes, String keyName){
        boolean isVerified = false;
        try {
            Signature verifySignature = Signature.getInstance("SHA1withRSA");
            verifySignature.initVerify(readPublicKey(keyName));
            verifySignature.update(input);
            isVerified = verifySignature.verify(signatureBytes);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            System.out.println("Invalid key!");
        }
        return isVerified;
    }
}
