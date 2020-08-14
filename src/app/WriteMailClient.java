package app;


import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.security.KeyStore;
import java.security.PrivateKey;
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
	private static final String keyStoreFileA= "./data/usera.jks";
	private static final String keyStoreFileB= "./data/userb.jks";
	private static final String keyStorePassA= "dunja";
	private static final String keyStorePassB= "ilija";
	private static final String keyStoreAAlias= "dunja";
	private static final String keyStoreBAlias= "ilija";
	private static final String keyStorePassForPrivateKeyA= "dunja";
	private static final String keyStorePassForPrivateKeyB= "ilija";
	private static KeyStoreReader keyStoreReader= new KeyStoreReader();


	
	
	
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
			
			//initialization for body encryption 
			IvParameterSpec ivParameterSpec1 = IVHelper.createIV();
			byte [] iVP1= ivParameterSpec1.getIV(); // for mailbody
			aesCipherEnc.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec1);
			
			
			//encryption
			byte[] ciphertext = aesCipherEnc.doFinal(compressedBody.getBytes());
			String ciphertextStr = Base64.encodeToString(ciphertext);
			System.out.println("Crypted text: " + ciphertextStr);
			
			
			//initialization for subject encryption
			IvParameterSpec ivParameterSpec2 = IVHelper.createIV();
			byte [] iVP2= ivParameterSpec2.getIV(); // for mailbody
			aesCipherEnc.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec2);
			
			//encryption
			byte[] ciphersubject = aesCipherEnc.doFinal(compressedSubject.getBytes());
			String ciphersubjectStr = Base64.encodeToString(ciphersubject);
			System.out.println("Crypted subject: " + ciphersubjectStr);
			
			//file and password are forwarded
			KeyStore ksA= keyStoreReader.readKeyStore(keyStoreFileB, keyStorePassB.toCharArray());
			
			//for user B we take certificate and public key
			Certificate cB= keyStoreReader.getCertificateFromKeyStore(ksA,keyStoreBAlias);
			PublicKey pkB= keyStoreReader.getPublicKeyFromCertificate(cB);
			PrivateKey privateB= keyStoreReader.getPrivateKeyFromKeyStore(ksA, keyStoreBAlias, keyStorePassB.toCharArray());
			System.out.println("User B Certificate: "+ cB);
			System.out.println("Userb B Public Key: " + pkB);
			
			
			//encrypted session key (with user B public key)
			Cipher rsaChiperEnc= Cipher.getInstance("RSA/ECB/PKCS1Padding");
			
			//encryption with secret key
			rsaChiperEnc.init(Cipher.ENCRYPT_MODE, pkB);
			
			// encryption
			byte[] encodedSecretKey= rsaChiperEnc.doFinal(secretKey.getEncoded());
			//System.out.println("Crypted secret key: " + Base64.encodeToString(encodedSecretKey));
			
			//save key bytes and IV
			JavaUtils.writeBytesToFilename(KEY_FILE, secretKey.getEncoded());
			JavaUtils.writeBytesToFilename(IV1_FILE, ivParameterSpec1.getIV());
			JavaUtils.writeBytesToFilename(IV2_FILE, ivParameterSpec2.getIV());
			
			MailBody mailBody= new MailBody(ciphertext, iVP1, iVP2, encodedSecretKey);
			
        	MimeMessage mimeMessage = MailHelper.createMimeMessage(reciever, ciphersubjectStr, mailBody.toCSV());
        	MailWritter.sendMessage(service, "me", mimeMessage);
        	
        }catch (Exception e) {
        	e.printStackTrace();
		}
	}
}
