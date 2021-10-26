import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.*;
import java.util.Arrays;

public class DemoAsymmetricKeysAndSignature {
    public static void main(String[] args) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        //demoKeys();
        KeyPairGenerator pairGen = KeyPairGenerator.getInstance("RSA");
        KeyPair pair = pairGen.generateKeyPair();
        PrivateKey ks = pair.getPrivate();
        PublicKey kv = pair.getPublic();
        byte[] msg = {'a','u','l','a','.'};
        byte[] sig = sign(msg, ks);
        System.out.print(sig.length);
        System.out.println(Arrays.toString(sig));
        // corrupt signature
        // sig[0]='x';
        System.out.println(verify(msg, sig, kv));

    }

    private static void demoKeysInternals() throws NoSuchAlgorithmException {
        // symmetric key generator
        KeyPairGenerator pairGen = KeyPairGenerator.getInstance("RSA");
        KeyPair pair = pairGen.generateKeyPair();

        PublicKey publicKey = pair.getPublic();
        PrivateKey privateKey = pair.getPrivate();

        System.out.println("Public key: " + publicKey);
        System.out.println("Private key: " + privateKey);

        // asymmetric key generator
        KeyGenerator secretKeyGen = KeyGenerator.getInstance("AES");
        SecretKey secretKey = secretKeyGen.generateKey();
        byte[] rawKey = secretKey.getEncoded();
        System.out.println(Arrays.toString(rawKey));
    }

    public static byte[] sign(byte[] msg, PrivateKey ks) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        Signature sig = Signature.getInstance("SHA512withRSA");
        sig.initSign(ks);
        sig.update(msg);
        byte[] result = sig.sign();
        return result;
    }

    public static boolean verify(byte[] msg, byte[] s, PublicKey kv) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature sig = Signature.getInstance("SHA512withRSA");
        sig.initVerify(kv);
        sig.update(msg);
        return sig.verify(s);
    }

}
