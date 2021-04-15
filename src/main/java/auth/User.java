package auth;

import fileSystem.SSFolder;

import javax.crypto.SecretKey;

public class User {
    private final String username;
    private String password;
    private final int hashAlgorithmCode;
    private final int cryptoAlgorithmCode;
    private byte[] salt;
    private SSFolder root;
    private SecretKey symmetricKey;

    public User(String username, String password, byte[] salt, int hashAlgorithmCode, int cryptoAlgorithmCode) {
        this.username = username;
        this.password = password;
        this.salt = salt;
        this.hashAlgorithmCode = hashAlgorithmCode;
        this.cryptoAlgorithmCode = cryptoAlgorithmCode;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
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

    public void setSalt(byte[] salt) {
        this.salt = salt;
    }

    public SecretKey getSymmetricKey() {
        return symmetricKey;
    }

    public void setSymmetricKey(SecretKey symmetricKey) {
        this.symmetricKey = symmetricKey;
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
