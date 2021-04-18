import auth.User;
import cryptoUtils.CryptoUtils;
import fileSystem.SSFile;
import fileSystem.SSFileSystem;
import fileSystem.SSFolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.awt.*;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.reflect.InvocationTargetException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

public class Main {

    public static final String ACTION_NOT_ALLOWED = "Action not allowed in this folder!";
    public static final String LOGOUT = "logout";
    public static final String SHARED = "shared";
    public static final String MESSAGE_FOR = "_message_for_";
    public static final String MESSAGES_FOLDER = "messages";
    public static final String TEMP_FOLDER = "temp";
    public static final String USERS_FOLDER = "users";
    public static final String USERS_TXT = "users.txt";

    public static void main(String[] args) throws IOException {
        Security.addProvider(new BouncyCastleProvider());
        SSFolder currentFolder;
        List<User> allUsers;
        if(Utils.checkIfFileExists(Paths.get("").toAbsolutePath() + File.separator + USERS_FOLDER
                                                                            + File.separator + USERS_TXT)) {
            allUsers = Utils.readAllUsers();
        } else {
            allUsers = new ArrayList<>();
        }

        SSFileSystem fileSystem = SSFileSystem.deserialize();
        if(fileSystem == null){
            fileSystem = new SSFileSystem();
        }
        Utils.writeWelcomeMessage();
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(System.in));
        String command = "";
        while (true){
            System.out.print(">");
            command = bufferedReader.readLine();
            switch (command) {
                case "register" -> {
                    String username;
                    String password;
                    String reenteredPassword;
                    System.out.print("Enter username: ");
                    username = bufferedReader.readLine();
                    if(username.length() > 10){
                        System.out.println("Username too long!" + "\nMaximum username length is 10 characters.");
                        break;
                    }
                    if(Utils.checkIfFileExists(Paths.get("").toAbsolutePath() + File.separator + USERS_FOLDER
                                              + File.separator + USERS_TXT) && Utils.checkUserExists(username)){
                        System.out.println("Username already exists\n");
                        break;
                    }
                    System.out.print("\nEnter password: ");
                    password = bufferedReader.readLine();
                    System.out.print("\nConfirm password: ");
                    reenteredPassword = bufferedReader.readLine();
                    if(password.equals(reenteredPassword)) {
                        System.out.println("""
                                MD5           1
                                SHA-256       2
                                SHA-512       3
                                """.replace("\s", "."));
                        System.out.print("Choose hash algorithm for your account: ");
                        String code = bufferedReader.readLine();
                        if(code == null || code.equals("")){
                            code = "3";
                        }
                        int hashCode = Integer.parseInt(code);
                        if(hashCode < 1 || hashCode > 3){
                            System.out.println("""
                                                Wrong hash algorithm code!
                                                Default algorithm will be used: SHA-512
                                                """);
                        }
                        System.out.println("""
                                DES           1
                                RC4           2
                                AES           3
                                """.replace("\s", "."));
                        System.out.print("Choose cypher algorithm for your account: ");
                        code = bufferedReader.readLine();
                        if(code == null || code.equals("")){
                            code = "3";
                        }
                        int cypherCode = Integer.parseInt(code);
                        if(cypherCode < 1 || cypherCode > 3){
                            System.out.println("""
                                                Wrong cypher algorithm code!
                                                Default algorithm will be used: AES
                                                """);
                        }
                        User newUser;
                        try {
                            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
                            byte[] salt = new byte[32];
                            random.nextBytes(salt);
                            String encryptedPassword = CryptoUtils.encryptPassword(password, salt, hashCode);
                            newUser = new User(username, encryptedPassword, salt, hashCode, cypherCode,
                                               CryptoUtils.generateKey(cypherCode));
                            allUsers.add(newUser);
                        } catch (NoSuchAlgorithmException e) {
                            System.out.println("No such algorithm");
                            break;
                        }
                        if (Utils.writeUser(newUser)) {
                            System.out.println("New user successfully registered!\nCreating new user directory...\n");
                            CryptoUtils.generateCertificate(username);
                            newUser.setRoot(fileSystem.addNewFolder(username + "/"));
                        }
                    } else {
                        System.out.println("\nPasswords do not match.");
                    }
                }

                case "login" -> {
                    String username;
                    String password;
                    User currentUser;
                    if(!Utils.checkIfFileExists(Paths.get("").toAbsolutePath() + File.separator + USERS_FOLDER
                                                                                         + File.separator + USERS_TXT)){
                        System.out.println("No users registered!\n");
                        break;
                    }
                    System.out.print("Enter username: ");
                    username = bufferedReader.readLine();
                    if(Utils.checkUserExists(username)){
                        Optional<User> optionalUser = allUsers.stream().filter(user -> user.getUsername().equals(username)).findFirst();
                        if(optionalUser.isPresent()) {
                            currentUser = optionalUser.get();
                            System.out.print("Enter password: ");
                            password = bufferedReader.readLine();
                            String passwordHash = CryptoUtils.encryptPassword(password, currentUser.getSalt(),
                                                                              currentUser.getHashAlgorithmCode());
                            if(passwordHash.equals(currentUser.getPassword())){
                                if(CryptoUtils.checkCertificateValidity(username)){
                                    System.out.println("Login successful!\n");
                                    currentFolder = fileSystem.findFolder(username);
                                    currentUser.setRoot(currentFolder);
                                    userWorkspace(currentUser, fileSystem);
                                } else {
                                    System.out.println("Certificate is not valid!");
                                }
                            } else {
                                System.out.println("Wrong password");
                            }
                        }
                    } else {
                        System.out.println(username + " does not exist in database!\n");
                    }
                    Utils.writeWelcomeMessage();
                }
                case "exit" ->{
                    boolean status = fileSystem.serialize();
                    int retryNumber = 0;
                    while (!status && retryNumber <= 100) {
                        for (User user : allUsers) {
                            System.out.println(user.getUsername());
                            fileSystem.addNewFolder(user.getUsername());
                        }
                        status = fileSystem.serialize();
                        retryNumber++;
                    }
                    if(retryNumber > 99){
                        System.out.println("File system has corrupted");
                        System.out.println("Could not restore root folders");
                    }
                    System.out.println("Good bye!");
                    bufferedReader.close();
                    return;
                }
                default -> System.out.println("Wrong command, please enter valid command!");
            }
        }
    }

    public static void userWorkspace(User currentUser, SSFileSystem fileSystem) throws IOException {
        SSFolder currentFolder = currentUser.getRoot();
        Utils.writeUserWelcomeMessage(currentUser.getUsername());
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(System.in));
        String exitCommand = "";
        String fullCommand;
        String[] commandList;
        String command;
        while (!exitCommand.equals(LOGOUT)){
            System.out.print(currentFolder.getPath() + "> ");
            fullCommand = bufferedReader.readLine();
            commandList = fullCommand.split(" ");
            command = commandList[0];
            switch (command){
                case "makefile" -> {
                    if(!Utils.checkArguments(commandList, 3)){
                        break;
                    }
                    if(currentFolder.equals(fileSystem.getSharedFolder())){
                        System.out.println(ACTION_NOT_ALLOWED);
                        break;
                    }
                    if(!commandList[1].endsWith(".txt")){
                        System.out.println("it is possible to create .txt files only!");
                        break;
                    }
                    if(currentFolder.findFile(commandList[1]) != null){
                        System.out.println("File with same name already exists!");
                        break;
                    }
                    byte[] bytes = CryptoUtils.symmetricEncrypt(fullCommand.split(" ", 3)[2].getBytes(),
                                                                currentUser.getCryptoAlgorithmCode(),
                                                                currentUser.getSymmetricKey());
                    currentFolder.addFile(commandList[1], false, bytes);
                }
                case "getfile" -> {
                    if(!Utils.checkArguments(commandList, 2)){
                        break;
                    }
                    if(currentFolder.equals(fileSystem.getSharedFolder())){
                        File message = new File(Paths.get("").toAbsolutePath() + File.separator
                                     + MESSAGES_FOLDER + File.separator + commandList[1]
                                     + MESSAGE_FOR + currentUser.getUsername() + ".txt");
                        if(!message.exists()){
                            System.out.println("Access denied!");
                            break;
                        }
                        String messageData = Files.readString(message.toPath());
                        String[] messageDetails = messageData.split(" # ");
                        byte[] encryptedSessionKey = Base64.getDecoder().decode(messageDetails[0]);
                        byte[] encryptedDigitalSignature = Base64.getDecoder().decode(messageDetails[1]);
                        String senderName = messageDetails[2];
                        if(!CryptoUtils.checkCertificateValidity(senderName)){
                            System.out.println(senderName + " does not have a valid certificate!");
                            break;
                        }
                        byte[] sessionKey = CryptoUtils.asymmetricDecrypt(encryptedSessionKey, currentUser.getUsername());
                        SecretKey secretKey = new SecretKeySpec(sessionKey, "AES");
                        byte[] digitalSignature = CryptoUtils.symmetricDecrypt(encryptedDigitalSignature, 3, secretKey);
                        byte[] fileData = Utils.getFile(currentFolder, commandList[1], 3, secretKey);
                        byte[] hashedFileData = CryptoUtils.hashData(fileData);
                        if(!CryptoUtils.verifySignature(hashedFileData, digitalSignature, senderName)){
                            System.out.println("Signatures do not match!");
                            break;
                        }
                        File sharedTemp = new File(Paths.get("").toAbsolutePath() + File.separator
                                        + TEMP_FOLDER + File.separator + commandList[1]);
                        Files.write(sharedTemp.toPath(), fileData);
                        Desktop.getDesktop().open(sharedTemp);
                        break;
                    }
                    File temp = new File(Paths.get("").toAbsolutePath() + File.separator
                              + TEMP_FOLDER + File.separator + commandList[1]);
                    byte[] bytes = Utils.getFile(currentFolder, commandList[1], currentUser.getCryptoAlgorithmCode(),
                                                                                currentUser.getSymmetricKey());
                    if(bytes.length != 0) {
                        Files.write(temp.toPath(), bytes);
                        Desktop.getDesktop().open(temp);
                    }
                }
                case "makefolder" -> {
                    if(!Utils.checkArguments(commandList, 2)){
                    break;
                    }
                    if(commandList[1].equals(SHARED)){
                        System.out.println("Can not create another shared folder");
                        break;
                    }
                    if(currentFolder.equals(fileSystem.getSharedFolder())){
                        System.out.println(ACTION_NOT_ALLOWED);
                        break;
                    }
                    if(currentFolder.findFile(commandList[1]) != null){
                        System.out.println("Folder with same name already exists!");
                        break;
                    }
                    currentFolder.addFile(commandList[1], true, null);
                }
                case "share" -> {
                    if(!Utils.checkArguments(commandList, 3)){
                        break;
                    }
                    if(!Utils.checkUserExists(commandList[2])){
                        System.out.println("User does not exist!");
                        break;
                    }
                    byte[] bytes = Utils.getFile(currentFolder, commandList[1], currentUser.getCryptoAlgorithmCode(), currentUser.getSymmetricKey());
                    if(bytes.length == 0){
                        break;
                    }
                    if(!CryptoUtils.checkCertificateValidity(commandList[2])){
                        System.out.println(commandList[2] + " does not have a valid certificate!");
                    }
                    if(fileSystem.getSharedFolder().findFile(commandList[1]) != null){
                        System.out.println("File with that name already exists!");
                        break;
                    }
                    PublicKey receiverPublicKey = CryptoUtils.readPublicKey(commandList[2]);
                    if(receiverPublicKey == null){
                        break;
                    }
                    byte[] hashedData = CryptoUtils.hashData(bytes);
                    byte[] digitalSignature = CryptoUtils.signFile(hashedData, currentUser.getUsername());
                    SecretKey sessionKey = CryptoUtils.generateKey(3);
                    byte[] encodedKey = sessionKey.getEncoded();
                    byte[] encryptedSessionKey = CryptoUtils.asymmetricEncrypt(encodedKey, commandList[2]);
                    byte[] encryptedDigitalSignature = CryptoUtils.symmetricEncrypt(digitalSignature, 3, sessionKey);
                    File message = new File(Paths.get("").toAbsolutePath() + File.separator + MESSAGES_FOLDER + File.separator + commandList[1] + MESSAGE_FOR + commandList[2] + ".txt");
                    String messageData = Base64.getEncoder().encodeToString(encryptedSessionKey) + " # "
                                       + Base64.getEncoder().encodeToString(encryptedDigitalSignature) + " # "
                                       + currentUser.getUsername();
                    Files.writeString(message.toPath(), messageData);
                    fileSystem.getSharedFolder().addFile(commandList[1], false, CryptoUtils.symmetricEncrypt(bytes, 3, sessionKey));
                }
                case "enter" -> {
                    if(!Utils.checkArguments(commandList, 2)){
                        break;
                    }
                    if(commandList[1].equals(SHARED)){
                        currentFolder = fileSystem.findFolder(SHARED);
                        break;
                    }
                    SSFile possiblyFolder = currentFolder.findFile(commandList[1]);
                    if(possiblyFolder instanceof SSFolder) {
                        currentFolder = (SSFolder) possiblyFolder;
                    } else if(possiblyFolder == null){
                        System.out.println(commandList[1] + " does not exist!");
                    } else {
                        System.out.println(commandList[1] + " is not a folder!");
                    }
                }
                case "back" -> {
                    if(currentFolder.equals(currentUser.getRoot()) ){
                        System.out.println(currentFolder.getPath() + " is root folder!");
                        break;
                    } else if(currentFolder.equals(fileSystem.getSharedFolder())){
                        currentFolder = currentUser.getRoot();
                        break;
                    }
                    String newPath = currentFolder.getPath().replaceAll("[^\\/]*\\/$", "").replaceAll("^\\/", "");
                    currentFolder = fileSystem.findFolder(newPath);
                }
                case "list" -> {
                    System.out.println("Directories:");
                    if(currentFolder != fileSystem.getSharedFolder()) {
                        System.out.print(currentFolder.print(0, false));
                    }
                    System.out.print(fileSystem.getSharedFolder().print(0, false));

                }
                case "upload" -> {
                    if(currentFolder.equals(fileSystem.getSharedFolder())){
                        System.out.println(ACTION_NOT_ALLOWED);
                        break;
                    }
                    final File[] newFile = new File[1];
                    try {
                        SwingUtilities.invokeAndWait(() -> newFile[0] = Utils.filePicker());
                    } catch (InterruptedException | InvocationTargetException e) {
                        System.out.println("Could not open File Chooser!");
                        Thread.currentThread().interrupt();
                        break;
                    }
                    if(newFile[0] == null){
                        System.out.println("File not selected!");
                        break;
                    }
                    byte[] bytes = CryptoUtils.symmetricEncrypt(Files.readAllBytes(newFile[0].toPath()), currentUser.getCryptoAlgorithmCode(),currentUser.getSymmetricKey());
                    currentFolder.addFile(newFile[0].getName(), false, bytes);
                }
                case "download" -> {
                    if(!Utils.checkArguments(commandList, 2)){
                        break;
                    }
                    if(currentFolder.equals(fileSystem.getSharedFolder())){
                        System.out.println(ACTION_NOT_ALLOWED);
                        break;
                    }
                    SSFile tempFile = currentFolder.findFile(commandList[1]);
                    if(tempFile == null){
                        System.out.println("File not found!");
                        break;
                    }
                    byte[] bytes = CryptoUtils.symmetricDecrypt(tempFile.getContent(), currentUser.getCryptoAlgorithmCode(), currentUser.getSymmetricKey());
                    final File[] newFile = new File[1];
                    try {
                        SwingUtilities.invokeAndWait(() -> newFile[0] = Utils.folderPicker());
                    } catch (InterruptedException | InvocationTargetException e) {
                        System.out.println("Could not open Directory Chooser!");
                        Thread.currentThread().interrupt();
                        break;
                    }
                    if(newFile[0] == null) {
                        System.out.println("File not selected");
                        break;
                    }
                    File fileToWrite = new File(newFile[0].getAbsolutePath() + File.separator + commandList[1]);
                    Files.write(fileToWrite.toPath(), bytes);
                }
                case "delete" -> {
                    SSFile tempFile = currentFolder.findFile(commandList[1]);
                    if(!Utils.checkArguments(commandList, 2)){
                        break;
                    }
                    if(currentFolder.equals(fileSystem.getSharedFolder())){
                        File message = new File(Paths.get("").toAbsolutePath() + File.separator + MESSAGES_FOLDER
                                     + File.separator + commandList[1] + MESSAGE_FOR + currentUser.getUsername() + ".txt");
                        if(!message.exists()){
                            System.out.println("No authorization to delete " + commandList[1]);
                            break;
                        }
                        currentFolder.delete(tempFile);
                        Files.delete(message.toPath());
                        if(message.exists()){
                            System.out.println("Message could not be deleted, please contact system administrator!");
                        }
                    }
                    if(commandList[1].equals(SHARED)){
                        System.out.println("Can not create another shared folder");
                        break;
                    }
                    if(tempFile == null){
                        System.out.println("File/Folder does not exist");
                        break;
                    }
                    if(currentFolder.delete(tempFile)){
                        System.out.println(commandList[1] + " Deleted successfully!");
                    } else {
                        System.out.println("Delete failed!");
                    }
                }
                case "edit" -> {
                    SSFile tempFile = currentFolder.findFile(commandList[1]);
                    if(!Utils.checkArguments(commandList, 3)){
                        break;
                    }
                    if(currentFolder.equals(fileSystem.getSharedFolder())){
                        System.out.println("This command is not allowed in shared folder!");
                    }
                    if(tempFile == null){
                        System.out.println("File does not exist!");
                        break;
                    }
                    currentFolder.delete(tempFile);
                    byte[] bytes = CryptoUtils.symmetricEncrypt(fullCommand.split(" ", 3)[2].getBytes(), currentUser.getCryptoAlgorithmCode(),currentUser.getSymmetricKey());
                    currentFolder.addFile(commandList[1], false, bytes);
                }
                case LOGOUT ->{
                    exitCommand = LOGOUT;
                }
                default -> {
                    System.out.println("Wrong command!");
                }
            }
        }
    }
}
