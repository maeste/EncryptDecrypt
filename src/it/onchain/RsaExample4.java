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

public class RsaExample4 {
    
    private static KeyPair getKeyPairFromKeyStore(String keyStoreName, String key) throws Exception {
        //Generated with:
        //  keytool -genkeypair -alias mykey -storepass s3cr3t -keypass s3cr3t -keyalg RSA -keystore keystore.jks

        InputStream ins = RsaExample4.class.getResourceAsStream(keyStoreName);

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
    
    
    private static byte[] sign(byte[] plainText, PrivateKey privateKey) throws Exception {
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update(plainText);

        return privateSignature.sign();

    }

    private static boolean verify(byte[] plainText, byte[] signature, PublicKey publicKey) throws Exception {
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(publicKey);
        publicSignature.update(plainText);

        return publicSignature.verify(signature);
    }

        
    public static void main(String... argv) throws Exception {
        //First generate a public/private key pair
        //KeyPair pair = generateKeyPair();
        KeyPair pair = getKeyPairFromKeyStore("/keystore.jks", "mykey");

        //Our secret message
        String message = "the answer to life the universe and everything";

        //Let's sign our message
        String plainText = "foobar";
        
        byte[] signature = sign(plainText.getBytes(UTF_8), pair.getPrivate());

        //Let's check the signature
        boolean isCorrect = verify(plainText.getBytes(UTF_8), signature, pair.getPublic());
        System.out.println("Signature correct: " + isCorrect);       
        
        
    }

}