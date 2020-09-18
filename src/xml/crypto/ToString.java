package xml.crypto;

import java.io.File;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;

public class ToString {
	private static final String emailFile= "./data/email_enc2.xml";
	
	public static void toString(Document doc) {
		try {
		File xmlFile= new File(emailFile);
		DocumentBuilderFactory dbFactory= DocumentBuilderFactory.newInstance();
		DocumentBuilder dBuilder= dbFactory.newDocumentBuilder();
		Document document= dBuilder.parse(xmlFile);
		System.out.println(document);
		}catch (Exception e) {
	         e.printStackTrace();
	    }
	}

}
