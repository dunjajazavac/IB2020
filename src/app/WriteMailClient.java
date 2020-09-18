package app;


import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Dictionary;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;
import javax.net.ssl.KeyStoreBuilderParameters;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.JavaUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import com.google.api.services.gmail.Gmail;

import model.keystore.KeyStoreReader;
import model.mailclient.MailBody;
import util.Base64;
import util.GzipUtil;
import util.IVHelper;
import xml.crypto.AsymmetricKeyDecryption;
import xml.crypto.AsymmetricKeyEncryption;
import xml.signature.SignEnveloped;
import xml.signature.VerifySignatureEnveloped;
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
	private static final String emailFile="./data/email_enc2.xml";
	private static KeyStoreReader keyStoreReader= new KeyStoreReader();


	static {
		// staticka inicijalizacija
		Security.addProvider(new BouncyCastleProvider());
		org.apache.xml.security.Init.init();
	}
	
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
            
            //kreiran xml fajl koji sadrzi subject i body
            createXML(subject, body);
            

            //potpisivanje fajla
            SignEnveloped signEnveloped = new SignEnveloped();
    		signEnveloped.testIt();
    		

            //enkriptovanje fajla
            AsymmetricKeyEncryption ake = new AsymmetricKeyEncryption();
    		ake.testIt();
    		
    		

    		File file = new File(emailFile);
            
            //slanje
    		MimeMessage mimeMessage = MailHelper.createMimeMessage(reciever, "", "", file);
        	MailWritter.sendMessage(service, "me", mimeMessage);
        	
       
            
            
            
//            
//            //Compression
//            String compressedSubject = Base64.encodeToString(GzipUtil.compress(subject));
//            String compressedBody = Base64.encodeToString(GzipUtil.compress(body));
//            
//            //Key generation
//            KeyGenerator keyGen = KeyGenerator.getInstance("AES"); 
//			SecretKey secretKey = keyGen.generateKey();
//			Cipher aesCipherEnc = Cipher.getInstance("AES/CBC/PKCS5Padding");
//			
//			//initialization for body encryption 
//			IvParameterSpec ivParameterSpec1 = IVHelper.createIV();
//			byte [] iVP1= ivParameterSpec1.getIV(); // for mailbody
//			aesCipherEnc.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec1);
//			
//			
//			//encryption
//			byte[] ciphertext = aesCipherEnc.doFinal(compressedBody.getBytes());
//			String ciphertextStr = Base64.encodeToString(ciphertext);
//			System.out.println("Crypted text: " + ciphertextStr);
//			
//			
//			//initialization for subject encryption
//			IvParameterSpec ivParameterSpec2 = IVHelper.createIV();
//			byte [] iVP2= ivParameterSpec2.getIV(); // for mailbody
//			aesCipherEnc.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec2);
//			
//			//encryption
//			byte[] ciphersubject = aesCipherEnc.doFinal(compressedSubject.getBytes());
//			String ciphersubjectStr = Base64.encodeToString(ciphersubject);
//			System.out.println("Crypted subject: " + ciphersubjectStr);
//			
//			//file and password are forwarded
//			KeyStore ksA= keyStoreReader.readKeyStore(keyStoreFileB, keyStorePassB.toCharArray());
//			
//			//for user B we take certificate and public key
//			Certificate cB= keyStoreReader.getCertificateFromKeyStore(ksA,keyStoreBAlias);
//			PublicKey pkB= keyStoreReader.getPublicKeyFromCertificate(cB);
//			PrivateKey privateB= keyStoreReader.getPrivateKeyFromKeyStore(ksA, keyStoreBAlias, keyStorePassB.toCharArray());
//			System.out.println("User B Certificate: "+ cB);
//			System.out.println("Userb B Public Key: " + pkB);
//			
//			
//			//encrypted session key (with user B public key)
//			Cipher rsaChiperEnc= Cipher.getInstance("RSA/ECB/PKCS1Padding");
//			
//			//encryption with secret key
//			rsaChiperEnc.init(Cipher.ENCRYPT_MODE, pkB);
//			
//			// encryption
//			byte[] encodedSecretKey= rsaChiperEnc.doFinal(secretKey.getEncoded());
//			//System.out.println("Crypted secret key: " + Base64.encodeToString(encodedSecretKey));
//			
//			//save key bytes and IV
//			JavaUtils.writeBytesToFilename(KEY_FILE, secretKey.getEncoded());
//			JavaUtils.writeBytesToFilename(IV1_FILE, ivParameterSpec1.getIV());
//			JavaUtils.writeBytesToFilename(IV2_FILE, ivParameterSpec2.getIV());
//			
//			MailBody mailBody= new MailBody(ciphertext, iVP1, iVP2, encodedSecretKey);
//			
//        	MimeMessage mimeMessage = MailHelper.createMimeMessage(reciever, ciphersubjectStr, mailBody.toCSV());
//        	MailWritter.sendMessage(service, "me", mimeMessage);
//        	
//        
//        	AsymmetricKeyDecryption akd= new AsymmetricKeyDecryption();
//        	akd.testIt();
//        	
//        	//SignEnveloped se= new SignEnveloped();
//        	//se.main(args);
//        	//VerifySignatureEnveloped vse= new VerifySignatureEnveloped();
//        	//vse.main(args);
//        	
      }catch (Exception e) {
      	e.printStackTrace();
	}
        

    
 }

public static void createXML(String subj, String body){
	final String xmlFilePath = "./data/email.xml";

	DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
	 
    DocumentBuilder documentBuilder;
     
    try {
    	documentBuilder = documentBuilderFactory.newDocumentBuilder();
    	Document document = documentBuilder.newDocument();
    	
    	Element root = document.createElement("email");
    	document.appendChild(root);
         
    	Element subject = document.createElement("subject");
    	root.appendChild(subject);
    	subject.setTextContent(subj);
    	
    	Element telo = document.createElement("body");
    	root.appendChild(telo);
    	telo.setTextContent(body);
		
		 
		Transformer transformer = TransformerFactory.newInstance().newTransformer();
		transformer.setOutputProperty(OutputKeys.INDENT, "yes"); 
	    DOMSource domSource = new DOMSource(document);
		 
		     
	    StreamResult streamResult = new StreamResult(new File(xmlFilePath));
	    transformer.transform(domSource, streamResult);
		     
		 
		System.out.println("Sacuvan fajl!");
		System.out.println("\nXml dom je uspesno kreiran!");

		

    } catch (Exception e) {
         e.printStackTrace();
    }
}
	
	


	

}
