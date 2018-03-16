package chatroom;

import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.HashSet;

public class chathubServer {
	public static void main(String[] args) throws Exception
	  {
		ChathubServerController servcon = new ChathubServerControllerImpl();
		//String alias = "chathub";
		  ECKeyExchange eckey  = new ECKeyExchange();
		  String cipherStr[] = {"ecdh-secp224r1+nocert+aes128/cbc","ecdh-secp256r1+x509+aes128/gcm128"};
	      System.out.println("Server want to start conversation....");
	      System.out.println(" Start ECDH key exchange befire actual chat begins");
	      servcon.sendCiphertoClient(cipherStr);
	      Certificate[] serverCertificates = CertificateUtil.getCertificateChain("/Users/Vamsi/Manju/mychatroom/chathub/chathubKeystore.jks","chathubpwd", "chathub");
	      servcon.sendCertificateChainToClient(serverCertificates);
	      Certificate[] clientCerts = servcon.recieveCertificateChainFromClient();
	      
	      if(servcon.validateCertificate(serverCertificates[1],clientCerts[0])){
	    	  
	    	  System.out.println("certificate is validated..");
		      KeyPair kp = eckey.genServerKeyPair();
		      System.out.println("kp.getPublic().getEncoded() .... "+kp.getPublic().getEncoded());
		      servcon.sendPublicKeyToClient(kp.getPublic().getEncoded());
		      byte[] cliPubByte = servcon.getBytesFromSocket();
		      System.out.println("cliPubByte "+cliPubByte);
		      
		      PublicKey cliPub = eckey.genPubKey(cliPubByte);
		      System.out.println("*****Received client public key :"+cliPub);
	
		      eckey.generateSharedKey(kp.getPrivate(),cliPub);
		      System.out.println("Received client public key :"+cliPubByte);
		      servcon.setEckey(eckey);
			  System.out.println(" Shared key established sucessfully ..");
			  servcon.serverChat();
	      }
	      else{
	    	  System.out.println("Not a valid certficate"); 
	      }
	  }            
}