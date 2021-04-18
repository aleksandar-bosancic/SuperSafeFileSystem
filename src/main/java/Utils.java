import auth.User;
import cryptoUtils.CryptoUtils;
import fileSystem.SSFile;
import fileSystem.SSFolder;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.filechooser.FileSystemView;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class Utils {
    public static boolean checkIfFileExists(String path){
        File file = new File(path);
        return file.exists();
    }

    public static void writeWelcomeMessage(){
        String ssTextBlock = """
                ╔════════════════════════════════════════════════╗
                ║          Welcome to SuperSafeFileSystem        ║
                ╠════════════════════════════════════════════════╣
                ║        command - description [arguments]       ║
                ║           register - register new user         ║
                ║            login - login into account          ║
                ║       exit - finish executing application      ║
                ╚════════════════════════════════════════════════╝
                                    """;
        System.out.print(ssTextBlock);

    }

    public static void writeUserWelcomeMessage(String username){
        String ssTextBlock = """
                ╔══════════════════════════════════════════════════════╗
                ║             Welcome to SuperSafeFileSystem           ║
                ║                      #username#                      ║
                ╠══════════════════════════════════════════════════════╣
                ║          command - description [arguments]           ║
                ║    makefile - make new txt file [file name, text]    ║
                ║  getfile - open file in default program [file name]  ║
                ║       makefolder - make new folder [folder name]     ║
                ║  share - share file to other user [file name, user]  ║
                ║        enter - enter next folder [folder name]       ║
                ║    back - return to previous folder [folder name]    ║
                ║   list - list files and folders in current folder    ║
                ║            upload - upload file from host            ║
                ║    download - download file to host [file name]      ║
                ║  delete - delete file or folder [file/folder name]   ║
                ║   edit - change txt file content [file name, text]   ║
                ║            logout - logout from system               ║
                ╚══════════════════════════════════════════════════════╝
                                    """;
        if(username.equals("")) {
            System.out.print(ssTextBlock.replace("#username#", "          "));
        } else {
            System.out.print(ssTextBlock.replace("#username#", centerString(10,username)));
        }
    }

    public static String centerString (int width, String s) {
        return String.format("%-" + width  + "s", String.format("%" + (s.length() + (width - s.length()) / 2) + "s", s));
    }

    public static boolean checkArguments(String[] commandList, int argumentNumber){
        if(commandList.length < argumentNumber){
            System.out.println("Insufficient number of arguments!");
            return false;
        }
        if(commandList[1].length() > 15){
            System.out.println("File name is too long!");
            return false;
        }
        return true;
    }

    public static List<User> readAllUsers(){
        User user;
        List<User> allUsers = new ArrayList<>();
        File file = new File(Paths.get("").toAbsolutePath() + File.separator + "users" + File.separator + "users.txt");
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
                user = new User(username, password, salt, hashAlgorithmCode, cryptoAlgorithmCode, secretKey);
                allUsers.add(user);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return allUsers;
    }

    public static boolean writeUser(User user){
        File file = new File(Paths.get("").toAbsolutePath() + File.separator + "users" + File.separator + "users.txt");
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
            String base64encodedStringLine = Base64.getEncoder().encodeToString(stringLine.getBytes());
            bufferedWriter.write(base64encodedStringLine);
            bufferedWriter.newLine();
        } catch (IOException e) {
            return false;
        }
        return status;
    }

    public static boolean checkUserExists(String username){
        return Utils.readAllUsers().stream().anyMatch(user -> user.getUsername().equals(username));
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
        JFileChooser chooser = new JFileChooser(FileSystemView.getFileSystemView().getHomeDirectory());
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
        JFileChooser chooser = new JFileChooser(FileSystemView.getFileSystemView().getHomeDirectory());
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        int returnVal = chooser.showOpenDialog(null);
        if(returnVal == JFileChooser.APPROVE_OPTION) {
            return chooser.getSelectedFile();
        }
        return null;
    }

    public static byte[] getFile(SSFolder currentFolder, String fileName, int cryptoCode, SecretKey key){
        SSFile tempFile = currentFolder.findFile(fileName);
        if(tempFile == null){
            System.out.println("File not found!");
            return new byte[0];
        }
        return CryptoUtils.symmetricDecrypt(tempFile.getContent(), cryptoCode, key);
    }
}
