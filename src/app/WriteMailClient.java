package app;


import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.Certificate;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.mail.internet.MimeMessage;
import javax.net.ssl.KeyStoreBuilderParameters;

import org.apache.xml.security.utils.JavaUtils;

import com.google.api.services.gmail.Gmail;

import model.keystore.KeyStoreReader;
import model.mailclient.MailBody;
import util.Base64;
import util.GzipUtil;
import util.IVHelper;
import support.MailHelper;
import support.MailWritter;

public class WriteMailClient extends MailClient {

	private static final String KEY_FILE = "./data/session.key";
	private static final String IV1_FILE = "./data/iv1.bin";
	private static final String IV2_FILE = "./data/iv2.bin";
	private static final String keyStoreFileA= ".data/usera.jks";
	private static final String keyStoreFileB= ".data/userb.jks";
	private static final String keyStorePassA= "usera";
	private static final String keyStoreAAlias= "usera";
	private static final String keyStoreBAlias= "userb";
	private static final String keyStorePassForPrivateKeyA= "usera";
	private static final String keyStorePassForPrivateKeyB= "userb";
	private static KeyStoreReader keyStoreReader= new KeyStoreReader();
	//private static MailBody mailBody= new MailBody();

	
	
	
	public static void main(String[] args) {
		
        try {
        	Gmail service = getGmailService();
            
        	System.out.println("Insert a reciever:");
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            String reciever = reader.readLine();
        	
            System.out.println("Insert a subject:");
            String subject = reader.readLine();
            
            
            System.out.println("Insert body:");
            String body = reader.readLine();
            
            
            //Compression
            String compressedSubject = Base64.encodeToString(GzipUtil.compress(subject));
            String compressedBody = Base64.encodeToString(GzipUtil.compress(body));
            
            //Key generation
            KeyGenerator keyGen = KeyGenerator.getInstance("AES"); 
			SecretKey secretKey = keyGen.generateKey();
			Cipher aesCipherEnc = Cipher.getInstance("AES/CBC/PKCS5Padding");
			
			//inicijalizacija za sifrovanje 
			IvParameterSpec ivParameterSpec1 = IVHelper.createIV();
			aesCipherEnc.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec1);
			
			
			//sifrovanje
			byte[] ciphertext = aesCipherEnc.doFinal(compressedBody.getBytes());
			String ciphertextStr = Base64.encodeToString(ciphertext);
			System.out.println("Kriptovan tekst: " + ciphertextStr);
			
			
			//inicijalizacija za sifrovanje 
			IvParameterSpec ivParameterSpec2 = IVHelper.createIV();
			aesCipherEnc.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec2);
			
			byte[] ciphersubject = aesCipherEnc.doFinal(compressedSubject.getBytes());
			String ciphersubjectStr = Base64.encodeToString(ciphersubject);
			System.out.println("Kriptovan subject: " + ciphersubjectStr);
			
			//fajl i lozinka za pristup se prosledjuju
			KeyStore ks= keyStoreReader.readKeyStore(keyStoreFileA, keyStorePassA.toCharArray());
			
			//za korisnika B uzimamo sertifikat i javni kljuc
			Certificate cB= keyStoreReader.getCertificateFromKeyStore(ks,keyStoreBAlias);
			PublicKey pkB= keyStoreReader.getPublicKeyFromCertificate(cB);
			
			//enkriptovanje session kljuca javnim kljucem od korisnika B
			Cipher rsaChiperEnc= Cipher.getInstance("RSA/ECB/PKCS1Padding","BC");
			
			//enkripcija tajnim kljucem
			rsaChiperEnc.init(Cipher.ENCRYPT_MODE, pkB);
			
			//kriptovanje
			byte[] encodedSecretKey= rsaChiperEnc.doFinal(secretKey.getEncoded());
			System.out.println("Kriptovani tajni kljuc: " + Base64.encodeToString(encodedSecretKey));
			
			//snimaju se bajtovi kljuca i IV.
			JavaUtils.writeBytesToFilename(KEY_FILE, secretKey.getEncoded());
			JavaUtils.writeBytesToFilename(IV1_FILE, ivParameterSpec1.getIV());
			JavaUtils.writeBytesToFilename(IV2_FILE, ivParameterSpec2.getIV());
			
        	MimeMessage mimeMessage = MailHelper.createMimeMessage(reciever, ciphersubjectStr, ciphertextStr);
        	MailWritter.sendMessage(service, "me", mimeMessage);
        	
        }catch (Exception e) {
        	e.printStackTrace();
		}
	}
}
