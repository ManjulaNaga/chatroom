package chatroom;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
//import java.security.cert.CertificateVerificationException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.security.*;
import java.util.HashSet;
import java.util.Set;

public class Validations {

    public static boolean isSelfSigned(X509Certificate cert) throws CertificateException, 
    NoSuchAlgorithmException, NoSuchProviderException {
        try {
            // Try to verify certificate signature with its own public key
            PublicKey key = cert.getPublicKey();
            cert.verify(key);
            return true;
        } catch (SignatureException sigEx) {
            // Invalid signature --> not self-signed
            return false;
        } catch (InvalidKeyException keyEx) {
            // Invalid key --> not self-signed
            return false;
        }
    }
    
    public static PKIXCertPathBuilderResult verifyCertificate(
            X509Certificate cert, Set<X509Certificate> additionalCerts,
            boolean verifySelfSignedCert) throws Exception {
      try {
            // Check for self-signed certificate
            if (!verifySelfSignedCert
                && isSelfSigned(cert)) {
                throw new Exception(
                        "The certificate is self-signed.");
            }

            // Prepare a set of trusted root CA certificates
            // and a set of intermediate certificates
            Set<X509Certificate> trustedRootCerts = new HashSet<X509Certificate>();
            Set<X509Certificate> intermediateCerts = new HashSet<X509Certificate>();
            for (X509Certificate additionalCert : additionalCerts) {
                if (isSelfSigned(additionalCert)) {
                    trustedRootCerts.add(additionalCert);
                } else {
                    intermediateCerts.add(additionalCert);
                }
            }

            // Attempt to build the certification chain and verify it
            PKIXCertPathBuilderResult verifiedCertChain = verifyCertificate(cert, trustedRootCerts,verifySelfSignedCert);

            // Check whether the certificate is revoked by the CRL
            // given in its CRL distribution point extension
            CRLVerifier.verifyCertificateCRLs(cert);

            // The chain is built and verified. Return it as a result
            return verifiedCertChain;
        } catch (CertPathBuilderException certPathEx) {
            throw new Exception(
                    "Error building certification path: "
                            + cert.getSubjectX500Principal(), certPathEx);
        } catch (CertificateVerificationException cvex) {
            throw cvex;
        } catch (Exception ex) {
            throw new Exception(
                    "Error verifying the certificate: "
                            + cert.getSubjectX500Principal(), ex);
        }
    }
    public class CertificateVerificationException extends Exception {
        private static final long serialVersionUID = 1L;
     
        public CertificateVerificationException(String message, Throwable cause) {
            super(message, cause);
        }
     
        public CertificateVerificationException(String message) {
            super(message);
        }
    }
}
