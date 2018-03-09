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

public class RsaExampleInteractive {
    
    private static KeyPair getKeyPairFromKeyStore(String keyStoreName, String key) throws Exception {
        //Generated with:
        //  keytool -genkeypair -alias mykey -storepass s3cr3t -keypass s3cr3t -keyalg RSA -keystore keystore.jks

        InputStream ins = RsaExampleInteractive.class.getResourceAsStream(keyStoreName);

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

    
    private static PublicKey getPublicKeyFromKeyStore(String keyStoreName, String key) throws Exception {
        //Generated with:
        //  keytool -genkeypair -alias otherkey -storepass s3cr3t -keypass s3cr3t -keyalg RSA -keystore keystore2.jks
    	//Export with:
    	// keytool -exportcert -alias otherkey -file otherkey.cert -keystore keystore2.jks
    	//import with:
    	// keytool -import -alias otherkey -file otherkey.cert -keystore keystore.jks

    	
        InputStream ins = RsaExampleInteractive.class.getResourceAsStream(keyStoreName);

        KeyStore keyStore = KeyStore.getInstance("JCEKS");
        keyStore.load(ins, "s3cr3t".toCharArray());   //Keystore password
        
        java.security.cert.Certificate cert = keyStore.getCertificate(key);
        return cert.getPublicKey();
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

    private static byte[] readFromFile(String fileName) throws FileNotFoundException, IOException {
		byte[] buffer = new byte[256];  
        FileInputStream is = new FileInputStream (fileName);  
        is.read (buffer);  
        is.close();
		return buffer;
	}

	private static void writeToFile(byte[] cipherText, String fileName) throws FileNotFoundException, IOException {
		FileOutputStream os = new FileOutputStream (fileName);  
        os.write (cipherText);  
        os.close();
	}
    
    public static void main(String... argv) throws Exception {
        if ("help".equalsIgnoreCase(argv[0])) {
        	System.out.println("use:");
        	System.out.println("encrypt <file name> <public_keyname>");
        	System.out.println("decrypt <file name> [private_keyname(default:mykey)]");
        	System.out.println("sign <file name> [private_keyname(default:mykey)]");
        	System.out.println("verify <sent file name> <signature file> <public_keyname>");
        }
        
        
        switch(argv[0]) {
        case "encrypt": {
        	 PublicKey publicKey = getPublicKeyFromKeyStore("/keystore.jks", argv[2]);
        	 byte[] buffer = readFromFile(argv[1]);
        	 byte[] cipherText = encrypt(new String(buffer), publicKey);
        	 writeToFile(cipherText, "encrypted_" + argv[1]); 
        	break;
        	}
        case "decrypt": {
        	String key = argv.length < 3 ? "mykey" : argv[2];
        	KeyPair pair = getKeyPairFromKeyStore("/keystore.jks", key);
        	byte[] buffer = readFromFile(argv[1]);
        	String decipheredMessage = decrypt(buffer, pair.getPrivate());
       	 	writeToFile(decipheredMessage.getBytes(), "decripted_" + argv[1]); 
        	break;
        	}
        case "sign": {
        	String key = argv.length < 3 ? "mykey" : argv[2];
        	KeyPair pair = getKeyPairFromKeyStore("/keystore.jks", key);
        	byte[] buffer = readFromFile(argv[1]);
        	byte[] signature = sign(buffer, pair.getPrivate());
       	 	writeToFile(signature, "signature_" + argv[1]); 
       	 	break;
        	}
        case "verify": {
        	PublicKey publicKey = getPublicKeyFromKeyStore("/keystore.jks", argv[3]);
       	 	byte[] sentFile = readFromFile(argv[1]);
       	 	byte[] signatureFIle = readFromFile(argv[2]);
    	 	boolean isCorrect = verify(sentFile, signatureFIle, publicKey);
    	 	System.out.println("Signature correct: " + isCorrect);
    	 	break;
        	}
        
        }
        
        
    }

}