import auth.User;
import cryptoUtils.CryptoUtils;
import fileSystem.SSFile;
import fileSystem.SSFileSystem;
import fileSystem.SSFolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.io.*;
import java.lang.reflect.InvocationTargetException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.List;
import java.util.*;

public class Main {

    public static void main(String[] args) throws IOException {
        Security.addProvider(new BouncyCastleProvider());
        SSFolder currentFolder;
        List<User> allUsers = null;
        if(Utils.checkIfFileExists("users/users.txt")) {
            allUsers = readAllUsers();
        } else {
            allUsers = new ArrayList<>();
        }
        SSFileSystem fileSystem = SSFileSystem.deserialize();
        if(fileSystem == null){
            fileSystem = new SSFileSystem();
        }
        currentFolder = fileSystem.getRoot();
//        ProcessBuilder builder = new ProcessBuilder(
//                "cmd.exe", "/c", "cd CA && .\\gencert.sh fifi");
//        builder.redirectErrorStream(true);
//        Process p = builder.start();
//        BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
//        String line;
//        while (true) {
//            line = r.readLine();
//            if (line == null) { break; }
//            System.out.println(line);
//        }

//        CryptoUtils.generateCertificate("tuki");

        Utils.writeWelcomeMessage("");
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(System.in));

//        fileSystem.addNewFolder("fifi/");
//        fileSystem.addNewFolder("carak/");
//        fileSystem.addNewFolder("pipi");
//        fileSystem.addNewFolder("kiki/newFolder/");
//        fileSystem.addNewFolder("kiki/newFolder2/");
//        fileSystem.addNewFolder("tuki");
//        fileSystem.addNewFolder("tuki/veliki/");
//        System.out.println("Current: " + currentFolder.print());
//        System.out.println(fileSystem);
//        String stringToSign = "Neki string sto ga treba potpisati.";
//        byte[] stringData = stringToSign.getBytes(StandardCharsets.UTF_8);
//
//        byte[] signatureBytes = CryptoUtils.signFile(stringData,"carak");
//
//        String base64encodedStringLine = Base64.getEncoder().encodeToString(signatureBytes);
//        System.out.println("Signature: " + base64encodedStringLine);
//
//        boolean isVerified = CryptoUtils.verifySignature(stringData, signatureBytes, "miki");
//
//        System.out.println("Verified: " + isVerified);

//        getCrl("list1");

//        File nonEncryptedFile = new File(Paths.get("").toAbsolutePath() + File.separator + "neki.txt");
//        byte[] bytes = Files.readAllBytes(nonEncryptedFile.toPath());
//        SecretKey key = CryptoUtils.generateKey("AES");
//        byte[] encBytes = CryptoUtils.symmetricEncrypt(bytes, 3, key);
//        Files.write(encryptedFile.toPath(), encBytes);
//        File decrypted = new File(current.toAbsolutePath().toString() + File.separator + "encfile.txt");
//        byte[] newBytes = Files.readAllBytes(decrypted.toPath());
//        byte[] newDecriptedBytes = CryptoUtils.symmetricDecrypt(newBytes, 3, key);
//        Files.write(newNonFile.toPath(), newDecriptedBytes);

//        Desktop.getDesktop().open(newNonFile);
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
                    if(Utils.checkIfFileExists("users/users.txt") && checkUserExists(username)){
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
                            newUser = new User(username, encryptedPassword, salt, hashCode, cypherCode, CryptoUtils.generateKey(cypherCode));
                            allUsers.add(newUser);
                        } catch (NoSuchAlgorithmException e) {
                            System.out.println("No such algorithm");
                            break;
                        }
                        if (writeUser(newUser)) {
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
                    if(!Utils.checkIfFileExists("users/users.txt")){
                        System.out.println("No users registered!\n");
                        break;
                    }
                    System.out.print("Enter username: ");
                    username = bufferedReader.readLine();
                    if(checkUserExists(username)){
                        Optional<User> optionalUser = allUsers.stream().filter(user -> user.getUsername().equals(username)).findFirst();
                        if(optionalUser.isPresent()) {
                            currentUser = optionalUser.get();
                            System.out.print("Enter password: ");
                            password = bufferedReader.readLine();
                            String passwordHash = CryptoUtils.encryptPassword(password, currentUser.getSalt(), currentUser.getHashAlgorithmCode());
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
                }
                case "exit" ->{
                    System.out.println("Good bye!");
                    fileSystem.serialize();
                    bufferedReader.close();
                    return;
                }
                default -> System.out.println("Wrong command, please enter valid command!");
            }
        }
    }

    public static void userWorkspace(User currentUser, SSFileSystem fileSystem) throws IOException {
        SSFolder currentFolder = currentUser.getRoot();
        Utils.writeWelcomeMessage(currentUser.getUsername());
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(System.in));
        String exitCommand = "";
        String fullCommand;
        String[] commandList;
        String command;
        while (!exitCommand.equals("logout")){
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
                        System.out.println("This command is not allowed in shared folder!");
                    }
                    byte[] bytes = CryptoUtils.symmetricEncrypt(fullCommand.split(" ", 3)[2].getBytes(), currentUser.getCryptoAlgorithmCode(),currentUser.getSymmetricKey());
                    currentFolder.addFile(commandList[1], false, bytes);
                }
                case "getfile" -> {
                    if(!Utils.checkArguments(commandList, 2)){
                        break;
                    }
                    SSFile tempFile = currentFolder.findFile(commandList[1]);
                    if(tempFile == null){
                        System.out.println("File not found!");
                        break;
                    }
                    File temp = new File(Paths.get("").toAbsolutePath() + File.separator + "Root" + File.separator + commandList[1]);
                    byte[] bytes = CryptoUtils.symmetricDecrypt(tempFile.getContent(), currentUser.getCryptoAlgorithmCode(), currentUser.getSymmetricKey());
                    Files.write(temp.toPath(), bytes);//tempFile.getContent());
                    Desktop.getDesktop().open(temp);
                }
                case "makefolder" -> {
                    if(!Utils.checkArguments(commandList, 2)){
                    break;
                }
                    if(commandList[1].equals("shared")){
                        System.out.println("Can not create another shared folder");
                        break;
                    }
                    if(currentFolder.equals(fileSystem.getSharedFolder())){
                        System.out.println("This command is not allowed in shared folder!");
                    }
//                    SSFolder folder = new SSFolder(currentFolder.getPath() + "/" + fullCommand.split(" ", 2)[1] + "/", currentUser.getUsername());
                    currentFolder.addFile(commandList[1], true, null);
                }
                case "message" -> {
                    if(!Utils.checkArguments(commandList, 3)){
                        break;
                    }
                }
                case "enter" -> {
                    if(!Utils.checkArguments(commandList, 2)){
                        break;
                    }
                    if(commandList[1].equals("shared")){
                        currentFolder = fileSystem.findFolder("shared/");
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
//                    System.out.println(newPath);
                    currentFolder = fileSystem.findFolder(newPath);
                }
                case "list" -> {
                    System.out.println("Directories:");
                    System.out.print(fileSystem.getSharedFolder().print(0, false));
                    System.out.print(currentFolder.print(0, false));
                }
                case "upload" -> {
                    final File[] newFile = new File[1];
                    try {
                        SwingUtilities.invokeAndWait(() -> newFile[0] = filePicker());
                    } catch (InterruptedException | InvocationTargetException e) {
                        e.printStackTrace();
                    }
                    byte[] bytes = CryptoUtils.symmetricEncrypt(Files.readAllBytes(newFile[0].toPath()), currentUser.getCryptoAlgorithmCode(),currentUser.getSymmetricKey());
                    currentFolder.addFile(newFile[0].getName(), false, bytes);
                }
                case "download" -> {
                    if(!Utils.checkArguments(commandList, 2)){
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
                        SwingUtilities.invokeAndWait(() -> newFile[0] = folderPicker());
                    } catch (InterruptedException | InvocationTargetException e) {
                        e.printStackTrace();
                    }
                    System.out.println(newFile[0].getAbsolutePath());
                    File fileToWrite = new File(newFile[0].getAbsolutePath() + File.separator + commandList[1]);
                    Files.write(fileToWrite.toPath(), bytes);
                }
                case "logout" ->{
                    exitCommand = "logout";
                }
                default -> {
                    System.out.println("Wrong command!");
                }
            }
        }
    }

    public static List<User> readAllUsers(){
        User user;
        List<User> allUsers = new ArrayList<>();
        File file = new File("users/users.txt");
        String line;
        try (BufferedReader reader = new BufferedReader(new FileReader(file))){
            while((line = reader.readLine()) != null){
                String decodedLine = new String(Base64.getDecoder().decode(line), StandardCharsets.UTF_8);
                String username = decodedLine.split(" # ")[0];
                String password = decodedLine.split(" # ")[1];
                byte[] salt = Base64.getDecoder().decode(decodedLine.split(" # ")[2]);
                int hashAlgorithmCode = Integer.parseInt(decodedLine.split(" # ")[3]);
                int cryptoAlgorithmCode = Integer.parseInt(decodedLine.split(" # ")[4]);
                byte[] secretKeyBytes = Base64.getDecoder().decode(decodedLine.split(" # ")[5]);
                String algorithm;
                switch (cryptoAlgorithmCode){
                    case 1 -> algorithm = "DES";
                    case 2 -> algorithm = "RC4";
                    default -> algorithm = "AES";
                }
                SecretKey secretKey = new SecretKeySpec(secretKeyBytes,algorithm);
                writeHash("ucitao: "+Base64.getEncoder().encodeToString(secretKeyBytes));
                user = new User(username, password, salt, hashAlgorithmCode, cryptoAlgorithmCode, secretKey);
                allUsers.add(user);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return allUsers;
    }

    public static boolean checkUserExists(String username){
        return readAllUsers().stream().anyMatch(user -> user.getUsername().equals(username));
    }

    public static boolean writeUser(User user){
        File file = new File("users/users.txt");
        boolean status = true;
        try (BufferedWriter bufferedWriter = new BufferedWriter(new FileWriter(file, true))){
            if(!file.exists()){
                status = file.createNewFile();
            }
            String stringLine = user.getUsername() + " # " + user.getPassword() + " # "
                                                   + Base64.getEncoder().encodeToString(user.getSalt()) + " # "
                                                   + user.getHashAlgorithmCode() + " # "
                                                   + user.getCryptoAlgorithmCode() + " # "
                                                   + Base64.getEncoder().encodeToString(user.getSymmetricKey().getEncoded());
            writeHash("upis" + Base64.getEncoder().encodeToString(user.getSymmetricKey().getEncoded()));
            String base64encodedStringLine = Base64.getEncoder().encodeToString(stringLine.getBytes());
            bufferedWriter.write(base64encodedStringLine);
            bufferedWriter.newLine();
        } catch (IOException e) {
            return false;
        }
        return status;
    }

    public static void writeHash(String hash) throws IOException {
        File file = new File("users/hash.txt");
        try (BufferedWriter bufferedWriter = new BufferedWriter(new FileWriter(file, true))) {
            bufferedWriter.write(hash);
            bufferedWriter.newLine();
        } catch (IOException ioException) {
            ioException.printStackTrace();
        }
    }

    public static File filePicker(){
        JFileChooser chooser = new JFileChooser();
        FileNameExtensionFilter filter = new FileNameExtensionFilter(
                "pdf,txt,png,jpeg,docx", "pdf", "txt", "png", "jpeg", "docx");
        chooser.setFileFilter(filter);
        int returnVal = chooser.showOpenDialog(null);
        if(returnVal == JFileChooser.APPROVE_OPTION) {
            return chooser.getSelectedFile();
        }
        return null;
    }

    public static File folderPicker(){
        JFileChooser chooser = new JFileChooser();
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        int returnVal = chooser.showOpenDialog(null);
        if(returnVal == JFileChooser.APPROVE_OPTION) {
            return chooser.getSelectedFile();
        }
        return null;
    }

//    public static void cls(){
//        for(int i = 0; i <= 50; i++)
//            System.out.println("\n");
//    }

    public static void cls() throws IOException, InterruptedException {
        new ProcessBuilder("cmd", "/c", "cls").inheritIO().start().waitFor();
    }
}
