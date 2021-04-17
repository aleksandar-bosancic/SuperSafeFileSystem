package fileSystem;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Objects;
import java.util.stream.IntStream;

public class SSFile implements Serializable {
    protected String path;
    protected String owner;
    protected byte[] content;

    public SSFile(String path, String owner, byte[] content) {
        this.path = path;
        this.owner = owner;
        this.content = content;
    }

    public String print(int depth, boolean isRoot) {
        if(isRoot){
            return "├─root";
        }
        String padding = "└─" + IntStream.range(0,depth*4).mapToObj(item -> "─").reduce("", (a,b)-> a+b);
        String name = path.split("/")[path.split("/").length - 1];
        String printOut = padding + name;
        if(name.matches("[a-z]*\\.[a-z]+")){
            printOut += "\r\n";
        }
        return printOut;
    }

    public String getPath() {
        return path;
    }

    public String getOwner(){
        return owner;
    }

    public byte[] getContent() {
        return content;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SSFile ssFile = (SSFile) o;
        return Objects.equals(path, ssFile.path) && Objects.equals(owner, ssFile.owner) && Arrays.equals(content, ssFile.content);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(path, owner);
        result = 31 * result + Arrays.hashCode(content);
        return result;
    }
}
