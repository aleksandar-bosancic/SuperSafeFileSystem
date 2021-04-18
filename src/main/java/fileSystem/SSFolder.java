package fileSystem;


import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
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

    public boolean delete(SSFile file){
        return files.remove(file);
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

    @Override
    public String toString() {
        return "SSFolder{" +
                "path='" + path + '\'' +
                ", owner='" + owner + '\'' +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        SSFolder folder = (SSFolder) o;
        return depth == folder.depth && Objects.equals(files, folder.files);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), files, depth);
    }
}
