package chatroom;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.HashSet;

public interface ClientController {

	public void clientChat() throws Exception;
	public byte[] getBytesFromSocket() throws Exception;
	public String[] recieveCipher() throws Exception ;
	public void sendPublicKeyToServer(byte[] pub) throws Exception;
	public byte[] recievePublicKeyfromServer() throws Exception;
	public byte[] charToBytesASCII(char[] buffer, int length);
	public void sendCertificateToServer(HashSet cert) throws Exception;
	public void sendCertificateChainToServer(Certificate[] certs) throws Exception;
	//public byte[] recieveCertificatefromServer() throws Exception;
	public Certificate[] recieveCertificateChainFromServer() throws Exception;
	public byte[]  getCertificateFromKeystore() throws 
	FileNotFoundException,KeyStoreException,IOException,CertificateException,NoSuchAlgorithmException,UnrecoverableEntryException;
	
	public boolean validateCertificate(Certificate selfcert,Certificate othercert) throws 
	InvalidKeyException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException;
}
