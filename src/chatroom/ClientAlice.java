package chatroom;

import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Base64;
import java.util.HashSet;

//import java.util.Base64.*;
public class ClientAlice {
	
	public static void main(String[] args) throws Exception
	{
		ClientAliceControllerImpl clicon = new ClientAliceControllerImpl();
		ECKeyExchange eckey  = new ECKeyExchange();
	      System.out.println("client want to start conversation....");
	      String[] cipherStr = clicon.recieveCipher();
	      ///if(cipherStr[1].equals("ecdh-secp224r1+nocert+aes128/gcm")){
	    	  System.out.println("cipher selected was "+cipherStr[1]);
	     // }
	    	 Certificate[] clientCerts = CertificateUtil.getCertificateChain("F:/masters docs/8 Quarter/network security/project/mychatroom/alice/aliceKeystore.jks", "Alicepwd", "mykey-alice");
	    	 clicon.sendCertificateChainToServer(clientCerts);
	    	 Certificate[] serverCerts = clicon.recieveCertificateChainFromServer();
	    	  
		      if(clicon.validateCertificate(clientCerts[1],serverCerts[0])){
		    	  System.out.println("certificate is validated..");
				    KeyPair kp = eckey.genServerKeyPair();
				      clicon.sendPublicKeyToServer(kp.getPublic().getEncoded());
				      byte[] cliPubByte = clicon.getBytesFromSocket();
				      //byte[] encliPubByte = Base64.getEncoder().encode(cliPubByte);
				      System.out.println("cliPubByte "+ new String(cliPubByte));
				      
				      PublicKey cliPub = eckey.genPubKey(cliPubByte);
				      System.out.println("*****Received client public key :"+cliPub);
			
				      eckey.generateSharedKey(kp.getPrivate(),cliPub);
				      System.out.println("Received client public key :"+cliPubByte);
				      clicon.setEckey(eckey);
					  System.out.println(" Shared key established sucessfully ..");
					 clicon.clientChat();
		      }
		      else{
		    	  System.out.println("Not a valid certficate"); 
		      }
	      
	    //  else{
	    	  System.out.println(":err cipher mismatch occured. ");
	      }    
	//}
}