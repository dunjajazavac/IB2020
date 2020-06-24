
package app;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;

import org.apache.xml.security.utils.JavaUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.google.api.services.gmail.Gmail;
import com.google.api.services.gmail.model.Message;

import model.keystore.KeyStoreReader;
import model.mailclient.MailBody;
import support.MailHelper;
import support.MailReader;
import util.Base64;
import util.GzipUtil;

public class ReadMailClient extends MailClient {

	public static long PAGE_SIZE = 3;
	public static boolean ONLY_FIRST_PAGE = true;
	
	private static final String KEY_FILE = "./data/session.key";
	private static final String IV1_FILE = "./data/iv1.bin";
	private static final String IV2_FILE = "./data/iv2.bin";
	
	public static KeyStoreReader keySoreReader= new KeyStoreReader();
	private static final String keyStoreFile1="./data/userb.jks";
	private static final String keyStorePassForPrivateKeyB= "userb";
	private static final String keyStoreAliasB= "userb";
	private static final String keyStorePassB= "userb";
	
	
	public static void main(String[] args) throws IOException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, MessagingException, NoSuchPaddingException, InvalidAlgorithmParameterException {
        // Build a new authorized API client service.
        Gmail service = getGmailService();
        ArrayList<MimeMessage> mimeMessages = new ArrayList<MimeMessage>();
        
        String user = "me";
        String query = "is:unread label:INBOX";
        
        List<Message> messages = MailReader.listMessagesMatchingQuery(service, user, query, PAGE_SIZE, ONLY_FIRST_PAGE);
        for(int i=0; i<messages.size(); i++) {
        	Message fullM = MailReader.getMessage(service, user, messages.get(i).getId());
        	
        	MimeMessage mimeMessage;
			try {
				
				mimeMessage = MailReader.getMimeMessage(service, user, fullM.getId());
				
				System.out.println("\n Message number " + i);
				System.out.println("From: " + mimeMessage.getHeader("From", null));
				System.out.println("Subject: " + mimeMessage.getSubject());
				System.out.println("Body: " + MailHelper.getText(mimeMessage));
				System.out.println("\n");
				
				mimeMessages.add(mimeMessage);
	        
			} catch (MessagingException e) {
				e.printStackTrace();
			}	
        }
        
        System.out.println("Select a message to decrypt:");
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
	        
	    String answerStr = reader.readLine();
	    Integer answer = Integer.parseInt(answerStr);
	    
		MimeMessage chosenMessage = mimeMessages.get(answer);
	   String content= chosenMessage.getContent().toString();
	   String toCSV[]= content.split("\\s");
	   System.out.println("\n csv \n:"+toCSV[1]);
	   MailBody mailBody= new MailBody(toCSV[1]);
	   byte [] encodedSecretKey= mailBody.getEncKeyBytes();
	   
	   System.out.println("\n secret key :\n"+ Base64.encodeToString(encodedSecretKey));
	   
	   //load keyStore
	   KeyStore keyStore= keySoreReader.readKeyStore(keyStoreFile1, keyStorePassB.toCharArray());
	   
	   //loaded privateKey for use of description
	   PrivateKey privateKey= keySoreReader.getPrivateKeyFromKeyStore(keyStore, keyStoreAliasB, keyStorePassForPrivateKeyB.toCharArray());
	   System.out.println("\n Read private key\n"+ privateKey);
	   
	   //TODO: Decrypt a message and decompress it. The private key is stored in a file.
	   Security.addProvider(new BouncyCastleProvider());
	   Cipher rsaCipherDec= Cipher.getInstance("RSA/EBC/PKCS1Padding");
	   rsaCipherDec.init(Cipher.DECRYPT_MODE, privateKey);
	   
	   byte[] key= rsaCipherDec.doFinal(encodedSecretKey);
	   System.out.println("\nThis is the key\n"+key.toString());
	   
	   Cipher aesCipherDec= Cipher.getInstance("AES/CBC/PKCS5Padding");
	   SecretKey secretKey= new SecretKeySpec(key, "AES");
	   
	   // initialization and decryption
	    byte[] iv1 = JavaUtils.getBytesFromFile(IV1_FILE);
		IvParameterSpec ivParameterSpec1 = new IvParameterSpec(iv1);
		aesCipherDec.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec1);
		
		String str =toCSV[0];
		byte[] bodyEnc = Base64.decode(str);
		String receivedBodyTxt = new String(aesCipherDec.doFinal(bodyEnc));
		String decompressedBodyText = GzipUtil.decompress(Base64.decode(receivedBodyTxt));
		System.out.println("Body text: " + decompressedBodyText);
		
		
		byte[] iv2 = JavaUtils.getBytesFromFile(IV2_FILE);
		IvParameterSpec ivParameterSpec2 = new IvParameterSpec(iv2);
		
		//initialization for decrypt
		aesCipherDec.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec2);
		
		//decompress and decrypt subject
		String decryptedSubjectText= new String(aesCipherDec.doFinal(Base64.decode(chosenMessage.getSubject())));
		String decompressedSubjectText= GzipUtil.decompress(Base64.decode(decryptedSubjectText));
		System.out.println("Subject text:"+new String(decompressedSubjectText));
		
	}
}
