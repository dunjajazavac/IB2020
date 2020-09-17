package xml.crypto;


import java.io.File;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class CreateXmlDom {
	
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
