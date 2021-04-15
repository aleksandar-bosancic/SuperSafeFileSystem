package fileSystem;

import java.io.*;

public class SSFileSystem implements Serializable {
    protected SSFolder root;
    protected SSFolder sharedFolder;
    protected String rootUser;

    public SSFileSystem() {
        root = new SSFolder("/", rootUser);
        sharedFolder = (SSFolder) root.addFile("shared", true, new byte[0]);
    }

    public SSFolder addNewFolder(String path){
        String[] splitedString = path.split("/");
        SSFolder temp = findFolder(path);
        if(temp.findFile(splitedString[splitedString.length - 1]) != null){
            return temp;
        }
        return (SSFolder) temp.addFile(splitedString[splitedString.length - 1], true, null);
    }

    public SSFolder findFolder(String path){
        String[] splitedString = path.split("/");
        SSFolder temp = root;
        for(int i = 1; i < splitedString.length - 1; i++) {
            System.out.println(splitedString[i]);
            SSFile file = temp.findFile(splitedString[i]);
            if (file instanceof SSFolder) {
                temp = (SSFolder) file;
            } else {
                return null;
            }
        }
        return temp;
    }

    public boolean serialize(){
        try {
            ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("Root/FileSystem.bin"));
            oos.writeObject(this);
            oos.close();
        } catch (IOException exception){
            return false;
        }
        return true;
    }
    public static SSFileSystem deserialize(){
        SSFileSystem fileSystem;
        try {
            ObjectInputStream ois = new ObjectInputStream(new FileInputStream("Root/FileSystem.bin"));
            fileSystem = (SSFileSystem) ois.readObject();
            ois.close();
        } catch (IOException | ClassNotFoundException exception){
            return null;
        }
        return fileSystem;
    }

    @Override
    public String toString() {
        return root.print(0, true);
    }
}
