
package app;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
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
	
   
	
	public static KeyStoreReader keySoreReader= new KeyStoreReader();
	private static final String keyStoreFile1="./data/userb.jks";
	private static final String keyStorePassForPrivateKeyB= "ilija";
	private static final String keyStoreAliasB= "ilija";
	private static final String keyStorePassB= "ilija";
	private static final String KEY_FILE = "./data/session.key";
	private static final String IV1_FILE = "./data/iv1.bin";
	private static final String IV2_FILE = "./data/iv2.bin";
	
	
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
		String body= MailHelper.getText(chosenMessage);
		
		// mailBody object
		MailBody mailBody= new MailBody(body);
		
		// take over vectors, encrypted key and body message

		IvParameterSpec ivParametarSpec1= new IvParameterSpec(mailBody.getIV1Bytes());
		IvParameterSpec IvParametarSpec2= new IvParameterSpec(mailBody.getIV2Bytes());
		
		byte [] message= mailBody.getEncMessageBytes();
		byte [] encSessionkey= mailBody.getEncKeyBytes();
	
		// get userB private key
		KeyStore userBkeyStore= keySoreReader.readKeyStore(keyStoreFile1, keyStorePassForPrivateKeyB.toCharArray());
		PrivateKey userBPrivateKey= keySoreReader.getPrivateKeyFromKeyStore(userBkeyStore, keyStoreAliasB, keyStorePassB.toCharArray());
		Certificate userBCertificate= keySoreReader.getCertificateFromKeyStore(userBkeyStore, keyStoreAliasB);
		PublicKey userBPublicKey= keySoreReader.getPublicKeyFromCertificate(userBCertificate);
		
		// descryption secret key with userB private key
		Cipher rsaCipherDec= Cipher.getInstance("RSA/ECB/PKCS1Padding");
		rsaCipherDec.init(Cipher.DECRYPT_MODE, userBPrivateKey);
		byte [] ssesionKeyDec= rsaCipherDec.doFinal(encSessionkey);	
		
		SecretKey secretKey= new SecretKeySpec(ssesionKeyDec, "AES");
		
		// initialization and descryption message body with secret key
		Cipher bodyCipherDec= Cipher.getInstance("AES/CBC/PKCS5Padding");
		bodyCipherDec.init(Cipher.DECRYPT_MODE,secretKey,ivParametarSpec1);
		byte [] receivedText= bodyCipherDec.doFinal(message);
		
		// decompression message body
		String decompressedMessageText= GzipUtil.decompress(Base64.decode(new String(receivedText)));
		
		// decryption i decompression subject
		bodyCipherDec.init(Cipher.DECRYPT_MODE,secretKey, IvParametarSpec2);
		String decryptedSubjectText= new String(bodyCipherDec.doFinal(Base64.decode(chosenMessage.getSubject())));
		String decompressedSubjectText= GzipUtil.decompress(Base64.decode(decryptedSubjectText));
		
		// print message
		System.out.println("Decompressed subject: " + decompressedSubjectText);
		System.out.println("Decompressed body: " + decompressedMessageText);
	}
}
	
		
		
		
		
		
		 


