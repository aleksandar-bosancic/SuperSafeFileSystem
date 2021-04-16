package fileSystem;


import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class SSFolder extends SSFile implements Serializable {
    private List<SSFile> files;
    private int depth;

    public SSFolder(String path, String owner) {
        super(path, owner, null);
        files = new ArrayList<>();
    }

    public SSFile findFile(String name) {
        Optional<SSFile> optional = files.stream().filter(item -> item.path.endsWith(name + "/")).findFirst();
        return optional.orElse(null);
    }

    public SSFile addFile(String name, boolean isFolder, byte[] content){
        if(isFolder){
            SSFolder folder = new SSFolder(path + name + "/", owner);
            files.add(folder);
            return folder;
        } else {
            SSFile file = new SSFile(path + name + "/", owner, content);
            files.add(file);
            return file;
        }
    }

    public String print(int depth, boolean isRoot) {
        String str = "";
        str += super.print(depth,isRoot) + System.lineSeparator();
        str += files.stream().map(item -> item.print(depth + 1, false)).reduce("", (a,b)-> a+b);
        return str;
    }

    public String print(){
        return this.getPath();
    }
}
