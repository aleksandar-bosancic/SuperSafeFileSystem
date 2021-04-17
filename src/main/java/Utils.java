import java.io.File;

public class Utils {
    public static boolean checkIfFileExists(String path){
        File file = new File(path);
        return file.exists();
    }
//    public static byte[] convertSalt(String salt){
//        byte[] byteSalt = new byte[32];
//        String[] strings = salt.split("\\[|\\]|, ");
//        for(int i = 1; i < strings.length; i++){
//            byteSalt[i - 1] = Byte.parseByte(strings[i]);
//        }
//        return byteSalt;
//    }
    public static void writeWelcomeMessage(String username){
        String ssTextBlock = """
                ╔════════════════════════════════════════════════╗
                ║          Welcome to SuperSafeFileSystem        ║
                ║                   #username#                   ║
                ║           register - register new user         ║
                ║            login - login into account          ║
                ║       exit - finish executing application      ║
                ╚════════════════════════════════════════════════╝
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
}
