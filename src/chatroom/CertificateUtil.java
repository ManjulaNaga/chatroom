package chatroom;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.HashSet;


public class CertificateUtil {

	public static HashSet getCertificate(String jksPath, String jksPassword) throws
	KeyStoreException, FileNotFoundException, IOException, NoSuchAlgorithmException, CertificateException
	{
		System.out.println("in get certificate()");
		HashSet<Certificate> certificates = new HashSet<>();

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        
        char[] password = jksPassword.toCharArray();

        java.io.FileInputStream fis = null;
        try {
            fis = new java.io.FileInputStream(jksPath);
            keyStore.load(fis, password);
        } finally {
            if (fis != null) {
                fis.close();
            }
        }
 
        Enumeration<String> enumeration  = keyStore.aliases();
    
        while(enumeration.hasMoreElements()){
        	String alias = enumeration.nextElement();
        	Certificate cert = keyStore.getCertificate(alias);
            certificates.add(cert);
        	System.out.println("Alias:" + alias + " certificates ..****************************************************** : "+ cert);
        }
        System.out.println("Certificate Length:" + certificates.size());
        return certificates;
	}

	public static Certificate[] getCertificateChain(String jksPath, String jksPassword, String alias)  throws
	KeyStoreException, FileNotFoundException, IOException, NoSuchAlgorithmException, CertificateException{
		// Certificate[] chain = keyStore.getCertificateChain(alias);
		System.out.println("in getCertificateChain()");
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());        
        char[] password = jksPassword.toCharArray();
        java.io.FileInputStream fis = null;
        try {
            fis = new java.io.FileInputStream(jksPath);
            keyStore.load(fis, password);
        } finally {
            if (fis != null) {
                fis.close();
            }
        }
        Certificate[] certCahin = keyStore.getCertificateChain(alias);
        for (int i = 0; i < certCahin.length; i++) {
        	System.out.println("Certificates ..****************************************************** : "+ certCahin[i]);
        	System.out.println("Certificate type : "+ certCahin[i].getType());
		}
        return certCahin;
	}

	/*  public KeyStore loadKeystore(,String jksPath,String jksPassword) 
			  throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException{
         
		  KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
          char[] password = jksPassword.toCharArray();
          java.io.FileInputStream fis = null;
          try {
              fis = new java.io.FileInputStream(jksPath);
              keystore.load(fis, password);
          } finally {
              if (fis != null) {
                  fis.close();
              }
          }
      	return keystore; 
      }*/
	public boolean varfyCertificate(String alias,String jksPassword,String jksPath) throws Exception{

		//KeyStore caKeystore =  loadKeystore("","") ;     
      
		// Verifying a certificate
		  KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
          char[] password = jksPassword.toCharArray();
          java.io.FileInputStream fis = null;
          try {
              fis = new java.io.FileInputStream(jksPath);
              keystore.load(fis, password);
          } finally {
              if (fis != null) {
                  fis.close();
              }
          }
        if(keystore.containsAlias(alias)){
        	Certificate cert = keystore.getCertificate(alias);
        	
    		PublicKey pubkey = cert.getPublicKey();
    		//try { 
    			cert.verify(pubkey);
    		/*} 
    		catch {
    		  System.out.println("An error occured...");
    		}finally{
    			System.out.println("in validate certificate()");
        }*/
		
        }
		return true;
	}
}
