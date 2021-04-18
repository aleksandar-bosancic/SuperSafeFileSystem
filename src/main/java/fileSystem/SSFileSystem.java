package fileSystem;

import java.io.*;

public class SSFileSystem implements Serializable {
    protected SSFolder root;
    protected SSFolder sharedFolder;

    public SSFileSystem() {
        root = new SSFolder("/", null);
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
        if(splitedString.length == 1){
            SSFile tempFile = root.findFile(splitedString[0]);
            if(tempFile instanceof SSFolder){
                return (SSFolder) tempFile;
            }
            return root;
        }
        for (String s : splitedString) {
            SSFile file = temp.findFile(s);
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
            try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("Root/FileSystem.bin"))) {
                oos.writeObject(this);
            }
        } catch (IOException exception){
            return false;
        }
        return true;
    }

    public static SSFileSystem deserialize(){
        SSFileSystem fileSystem;
        try {
            try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream("Root/FileSystem.bin"))) {
                fileSystem = (SSFileSystem) ois.readObject();
            }
        } catch (IOException | ClassNotFoundException exception){
            return null;
        }
        return fileSystem;
    }

    public SSFolder getSharedFolder() {
        return sharedFolder;
    }

    @Override
    public String toString() {
        return root.print(0, true);
    }
}
