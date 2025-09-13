import org.bouncycastle.jce.provider.BouncyCastleProvider;

class Main {
    public static void main(String[] args) {
        BouncyCastleProvider bc = new BouncyCastleProvider();
        System.out.println("ok" + bc.getName());
    }
}

