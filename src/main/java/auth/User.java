package auth;

import cryptoUtils.CryptoUtils;
import fileSystem.SSFolder;

import javax.crypto.SecretKey;

public class User {
    private final String username;
    private String password;
    private final int hashAlgorithmCode;
    private final int cryptoAlgorithmCode;
    private byte[] salt;
    private SSFolder root;
    private final SecretKey symmetricKey;

    public User(String username, String password, byte[] salt, int hashAlgorithmCode, int cryptoAlgorithmCode, SecretKey symmetricKey) {
        this.username = username;
        this.password = password;
        this.salt = salt;
        this.hashAlgorithmCode = hashAlgorithmCode;
        this.cryptoAlgorithmCode = cryptoAlgorithmCode;
        this.symmetricKey = symmetricKey;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    @Override
    public String toString() {
        return "User{" +
                "username='" + username + '\'' +
                ", password='" + password + '\'' +
                ", hashAlgorithm='" + hashAlgorithmCode + '\'' +
                ", cryptoAlgorithm='" + cryptoAlgorithmCode + '\'' +
                ", root=" + root +
                '}';
    }

    public byte[] getSalt() {
        return salt;
    }

    public SecretKey getSymmetricKey() {
        return symmetricKey;
    }

    public int getHashAlgorithmCode() {
        return hashAlgorithmCode;
    }

    public int getCryptoAlgorithmCode() {
        return cryptoAlgorithmCode;
    }

    public SSFolder getRoot() {
        return root;
    }

    public void setRoot(SSFolder root){
        this.root = root;
    }
}
