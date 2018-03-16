package chatroom;

import java.net.*;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;

import javax.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import java.io.*;
public class ClientAliceControllerImpl implements ClientController{
	Socket sock;
	BufferedReader iReader;
	OutputStream ostream;
	private static InetAddress host;
	String cipherStr;
	ECKeyExchange eckey;
	private ByteArrayOutputStream out;
	private ByteArrayInputStream in;
	private Authentication auth;
	ClientAliceControllerImpl() throws Exception{
		try
		{
			host = InetAddress.getLocalHost();
	    }
	    catch(UnknownHostException uhEx)
		{
	    	System.out.println("Host ID not found!");
	        System.exit(1);
	    }
		sock = new Socket(host, 3000);
		iReader = new BufferedReader(new InputStreamReader(sock.getInputStream()));
		ostream = sock.getOutputStream();
	    eckey = new  ECKeyExchange();
	    auth = new Authentication();
	    
	}
	public void clientChat() throws Exception{
		      // reading from keyboard (keyRead object)
		BufferedReader keyRead = new BufferedReader(new InputStreamReader(System.in));
		      // sending to client (pwrite object)
		PrintWriter pwrite = new PrintWriter(ostream, true);
		System.out.println("*****Start the chitchat, type and press Enter key*****");
		String enSendMsg;
		String receiveMessage, sendMessage;               
		while(true)
		{
				byte[] reMsg = getBytesFromSocket();
				System.out.println("Server :  " +auth.decryption(reMsg)); // displaying decrypted msg at  DOS prompt
				
				sendMessage = keyRead.readLine();  // keyboard reading
				System.out.println("Client :  "+sendMessage);
				enSendMsg = auth.encryption(sendMessage);
				pwrite.print(enSendMsg);       // sending encrypted msg to server
				pwrite.flush();                    // flush the data
				System.out.println("Reading data...");
		}  
	}
	public byte[] getBytesFromSocket() throws Exception{
		ByteArrayOutputStream baos = new ByteArrayOutputStream();  
		int bufferSize = 256;
		char[] charContent = new char[bufferSize];
		byte[] content = new byte[bufferSize];
		int bytesRead = -1;
		do {
			bytesRead = iReader.read( charContent );
			if (bytesRead > 0) {
				content = charToBytesASCII(charContent, bytesRead);
			    baos.write( content, 0, bytesRead );				
			}
			/////when byee is said end the chat....********************
		} while (bytesRead != -1 && bytesRead == bufferSize);

		byte[] retBuf = baos.toByteArray();
		baos.flush();
		baos.close();
		return retBuf;
	}

	public String[] recieveCipher() throws Exception {
		byte[] readBytes = getBytesFromSocket();
		String cipherStr = new String(readBytes);
		System.out.println("recieved ciphers from server.."+ new String(readBytes));
		String[] ciphers = cipherStr.split(",");
		return ciphers;
	}


	public byte[] charToBytesASCII(char[] buffer, int length) {
		 // char[] buffer = str.toCharArray();
		 byte[] b = new byte[length];
		 for (int i = 0; i < b.length; i++) {
		  b[i] = (byte) buffer[i];
		 }
		 return b;
		}

	public void sendCertificateToServer(HashSet cert) throws Exception{
		System.out.println("sending public key to server..");		
		Enumeration e = Collections.enumeration(cert);
			//while(e.hasMoreElements()){
				 byte[] encodedCert = Base64.getEncoder().encode(e.toString().getBytes());
				 out = new ByteArrayOutputStream();
				 out.write(encodedCert, 0, encodedCert.length);
				 out.writeTo(sock.getOutputStream());
				 System.out.println(":k1 "+encodedCert);
			//}
	}

	public void sendCertificateChainToServer(Certificate[] certs) throws Exception{
		System.out.println("sending certificates to server..");	
		for (int i = 0; i < certs.length; i++) {
			 byte[] encodedCert = certs[i].getEncoded();	// Base64.getEncoder().encode(
			 out = new ByteArrayOutputStream();
			 out.write(encodedCert, 0, encodedCert.length);
			 out.writeTo(sock.getOutputStream());
			 System.out.println(":k1 "+encodedCert);
		}	
	}
	
	public byte[] recievePublicKeyfromServer() throws Exception{
		System.out.println("in recieve certificate from client().......");
		byte[] readCert = getBytesFromSocket();
		System.out.println("recieved certificate from client.."+readCert);
		return readCert;
	}

/*public byte[] recieveCertificatefromServer() throws Exception{
	System.out.println("in recieve certificate from server().......");
	byte[] readBytes = getBytesFromSocket();
	System.out.println("recieved certificate from server.."+readBytes);
    return readBytes;
 }*/

public Certificate[] recieveCertificateChainFromServer() throws Exception {
	System.out.println("in recieve certificate chain from server().......");
	byte[] encCertBytes =  getBytesFromSocket();
	byte[] certBytes = encCertBytes;	// Base64.getDecoder().decode(
	System.out.println("Received:" + new String(certBytes));
	ByteArrayInputStream bis = new ByteArrayInputStream(certBytes);
	System.out.println("bis...."+	bis);
	Collection certs = CertificateFactory.getInstance("X.509").generateCertificates(bis);
	
		Certificate[] readCerts = new Certificate[2];
		int i=0;
		System.out.println("outside for loop...");
		for (Iterator iterator = certs.iterator(); iterator.hasNext(); i++) {
			Certificate object = (Certificate) iterator.next();
			readCerts[i] = object;
			System.out.println("Cert******************************************************* "+ i + " " + object);
		}
		System.out.println("recieved certificate from server..");
	    return readCerts;
}

public void sendPublicKeyToServer(byte[] pub) throws Exception{
System.out.println("sending public key to server..");	
 byte[] encodedPub = Base64.getEncoder().encode(pub);
 out = new ByteArrayOutputStream();
    //in = new ObjectInputStream(sock.getInputStream());
 out.write(encodedPub, 0, encodedPub.length);
 out.writeTo(sock.getOutputStream());
 System.out.println(":k1 "+encodedPub);
}

public byte[]  getCertificateFromKeystore() throws 
FileNotFoundException,KeyStoreException,IOException,CertificateException,NoSuchAlgorithmException{
	CertificateDetails certdetails = new CertificateDetails();
	X509Certificate cert = certdetails.getX509Certificate();
	byte[] certinbytes =  cert.getEncoded();
	return certinbytes;
}
	
public void setEckey(ECKeyExchange eckey) {
	this.eckey = eckey;
	auth.setEckey(eckey);
}
public boolean validateCertificate(Certificate selfcert,Certificate othercert) throws 
InvalidKeyException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException{
	System.out.println(" in validate certification()");
	PublicKey selfcapub = selfcert.getPublicKey();
	try{
		othercert.verify(selfcapub);
		return true;
	}catch(InvalidKeyException i){
		return false;
		}
	finally{
		
	}

}
}
