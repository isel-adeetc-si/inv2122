import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.Enumeration;
import java.util.Scanner;

public class KeystoreDemo {
    public static void main(String[] args) throws CertificateException, IOException, NoSuchAlgorithmException, KeyStoreException, UnrecoverableEntryException {
        KeyStore keystore = KeyStore.getInstance("PKCS12");
        FileInputStream fisKeyStore =
            new FileInputStream("<some file.pfx>");
        // password to ensure integrity
        keystore.load(fisKeyStore, "changeit".toCharArray());
        // list all alias entries in the keystore
        Enumeration<String> e = keystore.aliases();
        while (e.hasMoreElements()) {
            System.out.println("alias: " + e.nextElement());
        }
        // select an alias
        Scanner input = new Scanner(System.in);
        String alias = input.nextLine();
        // assumes selected entry is a private key
        KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) keystore.getEntry(
            alias,
            // password used to encrypt the private key
            // can be different from the password to ensure integrity
            new KeyStore.PasswordProtection("changeit".toCharArray())
        );
        System.out.println(entry);
    }
}
