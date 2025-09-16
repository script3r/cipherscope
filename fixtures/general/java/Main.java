package fixtures.general.java;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;

public class Main {
    public static void main(String[] args) throws Exception {
        KeyGenerator.getInstance("AES");
        Cipher.getInstance("AES/GCM/NoPadding");
    }
}
