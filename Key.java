package chatroom;
import java.security.SecureRandom;
import chatroom.ECKeyExchange;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;
//import javax.crypto*;
public class Key {
			//if conversation established:
	//a key is initialized
	//ECKeyExchange eckey =new ECKeyExchange();
	private byte[] key = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	private SecretKey secretkey;
	
	Key() throws Exception{
		key= new byte[16];

		Arrays.fill( key, (byte) 0 );
		//System.out.println("Generate a symetric key..."+key);	
		secretkey = new SecretKeySpec(key,0,key.length, "AES");
		//System.out.println("Secretkey is generated "+secretkey);
	}
	SecretKey getSecretKey(){
		return secretkey;
	}

}
