package chatroom;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

import chatroom.Key;
import java.security.PublicKey;
import java.security.PrivateKey;

public class Authentication {
	//public static final byte[] AES_IV = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	ECKeyExchange eckey;
	Key k;
	Constants con;
	public Authentication() throws Exception{ 	
		 eckey = new ECKeyExchange();
		//k = new Key();
		 con = new Constants();
	}	
	  
	String encryption(String originalText) throws Exception{
		//System.out.println(" Encrypting msg..");
	//	"ecdh-secp256r1+x509+aes128/gcm128"
		//Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		//use different cipher suites
		//SecretKey skey = eckey.getSecretKey();
		byte[] nonceBytes = Base64.getDecoder().decode(Constants.nouncestr);
		GCMParameterSpec spec = new GCMParameterSpec(Constants.GOM_TAG_LENGTH*8, nonceBytes);
		SecretKey skey = eckey.getSecretKey();
		//SecretKey skey = eckey.generateSharedKey(privKey, pubKey)
		//IvParameterSpec ivspec = new IvParameterSpec(AES_IV);
		SecureRandom r = new SecureRandom(); // should be the best PRNG;  
		byte[] iv = new byte[16];
		r.nextBytes(iv);
		// cipher.init(Cipher.ENCRYPT_MODE, skey, new IvParameterSpec(iv));
		cipher.init(Cipher.ENCRYPT_MODE, skey, spec);		
		//System.out.println("Encrypt the data...");
		byte[] plainText  = originalText.getBytes();
		long startTime = System.currentTimeMillis();
		long endTime = 0;    
		byte[] cipherText = cipher.doFinal(plainText);
		byte[] encodedCipherText = Base64.getEncoder().encode(cipherText);
		String encStr = new String(encodedCipherText);
		//System.out.println("Encrypted sucessfully");
		return encStr;
    }
	String decryption(byte[] encodedCipherText)throws Exception{
		//System.out.println(" Decrypting msg.....");
	
		byte[] cipherText = Base64.getDecoder().decode(encodedCipherText);
		SecretKey skey = eckey.getSecretKey();
		
		//IvParameterSpec ivspec = new IvParameterSpec(AES_IV);

		// Cipher cipherD = Cipher.getInstance("AES/CBC/PKCS5Padding");
		Cipher cipherD = Cipher.getInstance("AES/GCM/NoPadding");
		byte[] nonceBytes = Base64.getDecoder().decode(Constants.nouncestr);
		GCMParameterSpec spec = new GCMParameterSpec(Constants.GOM_TAG_LENGTH*8, nonceBytes);
		cipherD.init(Cipher.DECRYPT_MODE, skey, spec);
		byte[] stringBytes = cipherD.doFinal(cipherText);
		String str = new String(stringBytes);
		//System.out.println("Decrypted: "+str);
		return str;
	}

	public ECKeyExchange getEckey() {
		return eckey;
	}

	public void setEckey(ECKeyExchange eckey) {
		this.eckey = eckey;
	}

}
