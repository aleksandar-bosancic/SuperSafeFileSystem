package fileSystem;

import java.io.Serializable;
import java.util.stream.IntStream;

public class SSFile implements Serializable {
    protected String path;
    protected String owner;

    public byte[] getContent() {
        return content;
    }

    protected byte[] content;

    public SSFile(String path, String owner, byte[] content) {
        this.path = path;
        this.owner = owner;
        this.content = content;
    }

    public String print(int depth, boolean isRoot) {
        if(isRoot){
            return "root";
        }
        String padding = IntStream.range(0,depth*4).mapToObj(item -> " ").reduce("", (a,b)-> a+b);
        String name = path.split("/")[path.split("/").length - 1];
        return padding + name;
    }

    public String getPath() {
        return path;
    }

    public String getOwner(){
        return owner;
    }
}
