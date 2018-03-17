package chatroom;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.HashSet;

public interface ChathubServerController{
	public void serverChat() throws Exception;
	public void sendCiphertoClient(String[] cipherStr) throws Exception;
	public byte[] getBytesFromSocket()throws Exception;
	public void sendPublicKeyToClient(byte[] pub) throws Exception;
	public byte[] recievePublicKeyfromClient() throws Exception;
	public void sendCertificateToClient(HashSet cert) throws Exception;
	//public byte[] recieveCertificatefromClient() throws Exception;
	public Certificate[] recieveCertificateChainFromClient() throws Exception;
	public byte[] charToBytesASCII(char[] buffer, int length);
	//public byte[] getCertificateFromKeystore() throws Exception;
	public void sendCertificateChainToClient(Certificate[] certs) throws Exception;
	public boolean validateCertificate(Certificate selfcert,Certificate othercert) throws 
	InvalidKeyException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException;
	public void setEckey(ECKeyExchange eckey);
}
