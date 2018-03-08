package it.onchain;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;

import javax.crypto.Cipher;

public class RsaExample3 {

    private static KeyPair getKeyPairFromKeyStore(String keyStoreName, String key) throws Exception {
        //Generated with:
        //  keytool -genkeypair -alias mykey -storepass s3cr3t -keypass s3cr3t -keyalg RSA -keystore keystore.jks

        InputStream ins = RsaExample3.class.getResourceAsStream(keyStoreName);

        KeyStore keyStore = KeyStore.getInstance("JCEKS");
        keyStore.load(ins, "s3cr3t".toCharArray());   //Keystore password
        KeyStore.PasswordProtection keyPassword =       //Key password
                new KeyStore.PasswordProtection("s3cr3t".toCharArray());

        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(key, keyPassword);

        java.security.cert.Certificate cert = privateKeyEntry.getCertificate();
        PublicKey publicKey = cert.getPublicKey();
        PrivateKey privateKey = privateKeyEntry.getPrivateKey();

        return new KeyPair(publicKey, privateKey);
    }

    
    private static byte[] encrypt(String plainText, PublicKey publicKey) throws Exception {
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);

        return encryptCipher.doFinal(plainText.getBytes(UTF_8));
        
    }
    
    private static String decrypt(byte[] bytes, PrivateKey privateKey) throws Exception {
        
        Cipher decriptCipher = Cipher.getInstance("RSA");
        decriptCipher.init(Cipher.DECRYPT_MODE, privateKey);

        return new String(decriptCipher.doFinal(bytes), UTF_8);
    }

    
    public static void main(String... argv) throws Exception {
        KeyPair pair = getKeyPairFromKeyStore("/keystore.jks", "mykey");

        //Our secret message
        String message = "the answer to life the universe and everything";

        //Encrypt the message
        byte[] cipherText = encrypt(message, pair.getPublic());
        
        
        //Now decrypt it

        String decipheredMessage = decrypt(cipherText, pair.getPrivate());
        
        
        System.out.println("from String: " + decipheredMessage);
        
        
    }

}