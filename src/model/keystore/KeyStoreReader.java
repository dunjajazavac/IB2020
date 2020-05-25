package model.keystore;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

import model.keystore.IssuerData;

public class KeyStoreReader {
	
	public KeyStore readKeyStore(String keyStoreFilePath, char[] password) {
		KeyStore keyStore = null;
		try {
			
			keyStore = KeyStore.getInstance("JKS", "SUN");
			
			BufferedInputStream in = new BufferedInputStream(new FileInputStream(keyStoreFilePath));
			keyStore.load(in, password);
		} catch (KeyStoreException | NoSuchProviderException | NoSuchAlgorithmException | CertificateException | IOException e) {
			e.printStackTrace();
			System.err.println("\n[KeyStoreReader - readKeyStore] Greska prilikom ucitavanja KeyStore-a. Proveriti da li je putanja ispravna i da li je prosledjen dobra sifra za otvaranje KeyStore-a!\n");			
		}
		
		return keyStore;
	}
	
	
	public Certificate getCertificateFromKeyStore(KeyStore keyStore, String alias) {
		Certificate certificate = null;
		try {
			certificate = keyStore.getCertificate(alias);
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		
		if (certificate == null) {
			System.err.println("\n[KeyStoreReader - getCertificateFromKeyStore] Sertifikat je null. Proveriti da li je alias ispravan!\n");
		}
		
		return certificate;
	}
	
	
	
	
	public PublicKey getPublicKeyFromCertificate(Certificate certificate) {
		return certificate.getPublicKey();
	}

	
	
	
	}