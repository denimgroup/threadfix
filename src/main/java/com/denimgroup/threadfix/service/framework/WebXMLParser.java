package com.denimgroup.threadfix.service.framework;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

public class WebXMLParser {
	
	private WebXMLParser() {
		// intentionally inaccessible
	}
	
	// TODO we may be able to get better results with some more advanced logic here
	// maybe skip directories like "test", look in specific paths or at least check guesses
	// on the other hand I don't really see this being a bottleneck
	public static File findWebXMLInDirectory(File inputFile) {
		if (inputFile == null || !inputFile.exists()) {
			return null;
		}
		
    	List<File> directories = new ArrayList<>();
    	for (File file : inputFile.listFiles()) {
    		
    		if (file.isDirectory() && file.getName().equals("WEB-INF")) {
    			// we can skip ahead because this is where web.xml is supposed to be
    			return findWebXMLInDirectory(file);
    		} else if (file.isFile() && file.getName().equals("web.xml")) {
    			return file;
    		} else if (file.isDirectory()) {
    			directories.add(file);
    		}
    	}
    	
    	for (File directory : directories) {
    		File maybeWebXML = findWebXMLInDirectory(directory);
    		if (maybeWebXML != null) {
    			return maybeWebXML;
    		}
    	}
    	
    	return null;
	}
	
	public static ServletMappings getServletMappings(File file) {
		if (file == null || !file.exists()) {
			return new ServletMappings(null,null);
		}
		
		ServletParser parser = new WebXMLParser.ServletParser();
		
		try {
			SAXParserFactory factory = SAXParserFactory.newInstance();
			SAXParser saxParser = factory.newSAXParser();

			saxParser.parse(file, parser);
		} catch (SAXException e) {
			
		} catch (IOException e) {

		} catch (ParserConfigurationException e) {

		}
		
		return new ServletMappings(parser.mappings, parser.servlets);
	}
	
	// this class is private static so that it doesn't share state with its parent class
	// but is only accessible to this class.
	private static class ServletParser extends DefaultHandler {
		
		List<ClassMapping> servlets = new ArrayList<>();
		List<UrlPatternMapping> mappings = new ArrayList<>();
		
		String servletName = null, urlPattern = null, servletClass = null;
		StringBuilder builder = null;
		
		private static Set<String> tagsToGrab = new HashSet<>(Arrays.asList(
			new String[] { "servlet-name", "url-pattern", "servlet-class" }));
		
		@Override
		public void startElement(String uri, String localName,
				String qName, Attributes attributes)
				throws SAXException {

			if (tagsToGrab.contains(qName)) {
				builder = new StringBuilder();
			}
		}

		@Override
		public void endElement(String uri, String localName,
				String qName) throws SAXException {
			if (qName.equals("servlet-mapping")) {
				mappings.add(new UrlPatternMapping(servletName, urlPattern));
			} else if (qName.equals("servlet")) {
				servlets.add(new ClassMapping(servletName, servletClass));
			} else if (qName.equals("servlet-name")) {
				servletName = builder.toString();
				builder = null;
			} else if (qName.equals("url-pattern")) {
				urlPattern = builder.toString();
				builder = null;
			} else if (qName.equals("servlet-class")) {
				servletClass = builder.toString();
				builder = null;
			}
		}

		@Override
		public void characters(char ch[], int start, int length)
				throws SAXException {
			if (builder != null) {
				builder.append(ch, start, length);
			}
		}
	}
}
