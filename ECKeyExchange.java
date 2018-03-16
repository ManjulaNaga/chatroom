package chatroom;
import java.util.Base64;
import java.util.Base64.*;
import java.security.spec.*;


import java.security.*;
import java.security.spec.ECGenParameterSpec;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.math.BigInteger;

/*import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.util.encoders.Base64;
*/
	public class ECKeyExchange {
	


	  public KeyPair genClientKeyPair() throws Exception{
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
			/*ECGenParameterSpec ecsp;
			ecsp = new ECGenParameterSpec("secp256r1");
			kpg.initialize(ecsp);*/
			kpg.initialize(256);
			KeyPair kp = kpg.generateKeyPair();	
			System.out.println("+++++key pair is generated+++++");
			return kp;
			
	  }
	  

	  public KeyPair genServerKeyPair() throws Exception{
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
			/* ECGenParameterSpec ecsp;
			ecsp = new ECGenParameterSpec("secp256r1");
			kpg.initialize(ecsp); */
			kpg.initialize(256);
			KeyPair kp = kpg.generateKeyPair();	
			System.out.println("+++++key pair is generated+++++");
			return kp;		
	  }
	 public PublicKey genPubKey(byte[] keyb)  throws Exception{
		 System.out.println("in generate public key...");
		 	byte[] keyBytes = Base64.getDecoder().decode(keyb); 

		    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes); 
		    KeyFactory keyFactory = KeyFactory.getInstance("EC");
		    PublicKey publicKey = keyFactory.generatePublic(keySpec); 
		    System.out.println("publicKey generated from encoded bytes is "+publicKey);
		    return publicKey;
	 
	 }
	 SecretKey skey;
	 public SecretKey getSecretKey(){
		 return skey;
	 }
	 public void setSecretKey(SecretKey skey){
		 this.skey = skey;
	 }
	  public SecretKey generateSharedKey(PrivateKey privKey,PublicKey pubKey) throws Exception {
		    SecretKey skey ;
		  	KeyAgreement ka=KeyAgreement.getInstance("ECDH");
		    ka.init(privKey);
		    ka.doPhase(pubKey,true);
		    byte[] sb = ka.generateSecret();
		    /*try{
		    	BigInteger s=new BigInteger(1,sb);
		    	System.out.println("    //Shared secret key generated is "+ s);
		    	return s;
		    }
		    catch(NumberFormatException e)
		    {
		    	System.out.println(":err "+e);
		    	return null;
		    }
		   */
		    
		    skey = new SecretKeySpec(sb,0,sb.length,"ECDH");
		    System.out.println("Shared Key generated is==================== : "+skey);
		    setSecretKey(skey);
		    return skey;
		}
	}

