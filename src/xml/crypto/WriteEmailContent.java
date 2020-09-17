package xml.crypto;

import java.io.File;
import java.io.IOException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

public class WriteEmailContent {
	
	public static void writeEmailContent(String path) throws SAXException, IOException, ParserConfigurationException {
		try {
		File file = new File("./data/email_dec2.xml");
		
		DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();  
		DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();  
		Document document = documentBuilder.parse(file);  
		document.getDocumentElement().normalize();  
		NodeList s = document.getElementsByTagName("subject");
		Node subj = s.item(0);
		
		NodeList b = document.getElementsByTagName("body");
		Node body = b.item(0);
		
		System.out.print("\nSubject: " + subj.getTextContent());
		System.out.print("\nBody: " + body.getTextContent());
		
		}catch (Exception e) {
		         e.printStackTrace();
		    }
		}

		
	}


