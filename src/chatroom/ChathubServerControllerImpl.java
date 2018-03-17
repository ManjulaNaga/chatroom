package chatroom;
import javax.security.cert.CertificateEncodingException;
//import java.awt.List;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
//import java.io.File;
//import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
//import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
//import java.security.UnrecoverableEntryException;
//import java.security.cert.CertPath;
//import java.security.cert.Certificate;
//import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
//import java.security.cert.CertificateFactory;
//import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
//import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.security.cert.X509Certificate;
import java.security.cert.CertPath;
import java.security.cert.Certificate;


public class ChathubServerControllerImpl implements ChathubServerController{
	
	private ServerSocket sersock;
	private Socket sock;
	private ByteArrayOutputStream out;
	//private ByteArrayInputStream in;
	private Authentication auth;
	ECKeyExchange eckey ;
	BufferedReader iReader;
	CertificateDetails certdetails;
	HashSet<Certificate> certificates = new HashSet<>();

	ChathubServerControllerImpl() throws Exception{
		sersock = new ServerSocket(3000);	
	    sock = sersock.accept( ); 
	    eckey = new  ECKeyExchange(); 
	    auth = new Authentication();
	    certdetails = new CertificateDetails();
	} 
	public void serverChat() throws Exception{
	      System.out.println("Server  ready for chatting");
		      // reading from keyboard (keyRead object)
		BufferedReader keyRead = new BufferedReader(new InputStreamReader(System.in));
		      // sending to client (pwrite object)
		OutputStream ostream = sock.getOutputStream(); 
		PrintWriter pwrite = new PrintWriter(ostream, true);
		      // receiving from server ( receiveRead  object)
		InputStream istream = sock.getInputStream();
		BufferedReader receiveRead = new BufferedReader(new InputStreamReader(istream));
		System.out.println("*****Start the chitchat, type and press Enter key*****");
		String enSendMsg;
		String receiveMessage, sendMessage;               
		while(true)
		{
			sendMessage = keyRead.readLine();  // keyboard reading
			System.out.println("Server :  "+sendMessage);

			enSendMsg = auth.encryption(sendMessage);
			
			pwrite.print(enSendMsg);       // sending encrypted msg to server
			pwrite.flush();                    // flush the data
			System.out.println("Reading data...");
				byte[] reMsg = getBytesFromSocket();
				System.out.println("Client : "+auth.decryption(reMsg) ); // displaying decrypted msg at  DOS prompt			
		}   
	}
	public void  sendCiphertoClient(String[] cipherStr) throws Exception{
		System.out.println("sending cipher to client....");
		System.out.println(":ka "+cipherStr[0] +" , "+cipherStr[1]);
		
		out = new ByteArrayOutputStream();
	    //in = new ObjectInputStream(sock.getInputStream());
		for (int i = 0; i < cipherStr.length; i++) {
			String cipher = cipherStr[i];
			out.write(cipher.getBytes(), 0, cipher.length());
			if (i < cipherStr.length-1) {
				out.write(",".getBytes(), 0, ",".length());
			}
		}
		out.writeTo(sock.getOutputStream());
	 
	}

	
	public void sendCertificateToClient(HashSet cert) throws Exception{
		System.out.println("sending certificate to client..");	
		Enumeration e = Collections.enumeration(cert);
		//while(e.hasMoreElements()){
			 byte[] encodedCert = Base64.getEncoder().encode(e.toString().getBytes());
			 out = new ByteArrayOutputStream();
			 out.write(encodedCert, 0, encodedCert.length);
			 out.writeTo(sock.getOutputStream());
			 System.out.println(":k1 "+encodedCert);
		//}
	
	}

	public void sendCertificateChainToClient(Certificate[] certs) throws Exception{
		System.out.println("sending certificates to client..");	
		
		out = new ByteArrayOutputStream();
		for (int i = 0; i < certs.length; i++) {
			 byte[] cert = certs[i].getEncoded();
			 out.write(cert, 0, cert.length);
		}
		byte[] encodedCert = Base64.getEncoder().encode(out.toByteArray());
		ByteArrayOutputStream encOut = new ByteArrayOutputStream();
		encOut.write(encodedCert);
			 encOut.writeTo(sock.getOutputStream());
			 System.out.println(":k1 "+encodedCert);	
	}

	public void sendPublicKeyToClient(byte[] pub) throws Exception{
		
		System.out.println("sending public key to client..");	
		 byte[] encodedPub = Base64.getEncoder().encode(pub);
		 out = new ByteArrayOutputStream();
		    //in = new ObjectInputStream(sock.getInputStream());
		 out.write(encodedPub, 0, encodedPub.length);
		 out.writeTo(sock.getOutputStream());
		 System.out.println(":k1 "+ new String(encodedPub));

	}
	public byte[] recievePublicKeyfromClient() throws Exception{
		System.out.println("in recievePublicKeyfromclient().......");

		 InputStream istream = sock.getInputStream();
		   byte[] recPub = new byte[100];
		   int bytesRead = -1;
			 out = new ByteArrayOutputStream();

		    while(( bytesRead = istream.read(recPub))!= -1) { 
		    	System.out.println("+++++++");
		    	out.write(recPub,0,bytesRead);
		   }
			System.out.println("recieved public key from client.."+recPub);
		    return recPub;
	}
public boolean validateCertificate(Certificate selfcert,Certificate othercert) throws 
InvalidKeyException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException{
	
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
	
	/*public byte[] recieveCertificatefromClient() throws Exception{
		System.out.println("in recieve certificate from client().......");
		byte[] readCert = getBytesFromSocket();
			System.out.println("recieved certificate from client.."+readCert);
			CertificateFactory.getInstance("X.509").generateCertificates(sock.getInputStream());
			Certificate[] certs;
		    return readCert;
	}*/

	public Certificate[] recieveCertificateChainFromClient() throws Exception{
		System.out.println("in recieve certificate from client().......");
		byte[] encCertBytes =  getBytesFromSocket();
		byte[] certBytes = Base64.getDecoder().decode(encCertBytes);
		System.out.println("Received:" + new String(certBytes));
		ByteArrayInputStream bis = new ByteArrayInputStream(certBytes);
		Collection certs = CertificateFactory.getInstance("X.509").generateCertificates(bis);
			System.out.println("recieved certificate from client..");
			Certificate[] readCerts = new Certificate[2];
			int i=0;
			for (Iterator iterator = certs.iterator(); iterator.hasNext(); i++) {
				Certificate object = (Certificate) iterator.next();
				readCerts[i] = object;
				System.out.println("Cert "+ i + " " + object);
			}
		    return readCerts;
	}

	public byte[] charToBytesASCII(char[] buffer, int length) {
		 // char[] buffer = str.toCharArray();
		 byte[] b = new byte[length];
		 for (int i = 0; i < b.length; i++) {
		  b[i] = (byte) buffer[i];
		 }
		 return b;
		}
	
	
	public byte[] getBytesFromSocket() throws Exception{
		InputStream istream = sock.getInputStream();
		ByteArrayOutputStream baos = new ByteArrayOutputStream();  
		int bufferSize = 256;
		byte[] content = new byte[bufferSize]
				;  
		int bytesRead = -1;
		do {
			bytesRead = istream.read( content );
			if (bytesRead > 0) {
			    baos.write( content, 0, bytesRead );				
			}
		} while (bytesRead != -1 && bytesRead == bufferSize);
	
		byte[] retBuf = baos.toByteArray();
		baos.close();
		baos.flush();
		return retBuf;
	}
	
	public byte[]  getCertificateFromKeystore() throws 
	FileNotFoundException,KeyStoreException,IOException,CertificateException,NoSuchAlgorithmException,CertificateEncodingException{
		X509Certificate cert = certdetails.getX509Certificate();
		System.out.println("cert------------------------------" +cert);
		byte[] certinbytes =  cert.getEncoded();
		return certinbytes;
	}
	
	public void setEckey(ECKeyExchange eckey) {
		this.eckey = eckey;
		auth.setEckey(eckey);
	}
	
}

//.n/. ././n