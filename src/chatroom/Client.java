package chatroom;

import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Base64;
import java.util.HashSet;

//import java.util.Base64.*;

public class Client {
 	
	public static void main(String[] args) throws Exception
	{
		if (!(args[0].equals("alice") || args[0].equals("bob"))) {
			System.out.println("Invalid User!");
			return;
		}
		ClientControllerImpl clicon = new ClientControllerImpl();
		clicon.setName(args[0]);
		clicon.sendNameToServer(args[0]);
		ECKeyExchange eckey  = new ECKeyExchange();
	      System.out.println("client want to start conversation....");
	      String[] cipherStr = clicon.recieveCipher();
	    	  System.out.println("cipher selected was "+cipherStr[1]);
	    	  Certificate[] clientCerts;
	    	  if (args[0].equals("alice")) {
	    		  //clientName = "alice";
	    		  clientCerts = CertificateUtil.getCertificateChain("F:/masters docs/8 Quarter/network security/project/mychatroom/alice/aliceKeystore.jks", "Alicepwd", "mykey-alice");
			} else {
				clientCerts = CertificateUtil.getCertificateChain("F:/masters docs/8 Quarter/network security/project/mychatroom/bob/bobKeystore.jks", "Bobpwd", "mykey-bob");
			}
	    	 
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