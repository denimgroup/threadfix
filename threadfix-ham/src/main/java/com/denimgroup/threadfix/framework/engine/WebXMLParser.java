////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2013 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 2.0 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is ThreadFix.
//
//     The Initial Developer of the Original Code is Denim Group, Ltd.
//     Portions created by Denim Group, Ltd. are Copyright (C)
//     Denim Group, Ltd. All Rights Reserved.
//
//     Contributor(s): Denim Group, Ltd.
//
////////////////////////////////////////////////////////////////////////
package com.denimgroup.threadfix.framework.engine;

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

import com.denimgroup.threadfix.framework.util.SanitizedLogger;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

class WebXMLParser {

    private static final SanitizedLogger log = new SanitizedLogger("FrameworkCalculator");

    private WebXMLParser() {
		// intentionally inaccessible
	}
	
	@Nullable
    public static ServletMappings getServletMappings(@NotNull File file,
			ProjectDirectory projectDirectory) {
		ServletParser parser = new WebXMLParser.ServletParser();

		try {
			SAXParserFactory factory = SAXParserFactory.newInstance();
			SAXParser saxParser = factory.newSAXParser();

			saxParser.parse(file, parser);
		} catch (@NotNull IOException | SAXException | ParserConfigurationException e) {
			log.warn("Encountered exception while parsing mappings.", e);
		}
		
		return new ServletMappings(parser.mappings, parser.servlets, projectDirectory);
	}
	
	// this class is private static so that it doesn't share state with its parent class
	// but is only accessible to this class.
	private static class ServletParser extends DefaultHandler {
		
		@NotNull
        List<ClassMapping> servlets = new ArrayList<>();
		@NotNull
        List<UrlPatternMapping> mappings = new ArrayList<>();
		
		@Nullable
        String servletName = null, urlPattern = null, servletClass = null, contextConfigLocation = null;
		@NotNull
        StringBuilder builder = new StringBuilder();
		
		boolean getContextConfigLocation = false,
				grabText = false;
		
		private static final String 
			SERVLET_MAPPING = "servlet-mapping",
			SERVLET = "servlet",
			SERVLET_NAME = "servlet-name", 
			URL_PATTERN = "url-pattern", 
			SERVLET_CLASS = "servlet-class", 
			PARAM_NAME = "param-name", 
			PARAM_VALUE = "param-value",
			CONTEXT_CONFIG_LOCATION = "contextConfigLocation";
	
		@NotNull
        private static Set<String> tagsToGrab = new HashSet<>(Arrays.asList(
			new String[] { SERVLET_NAME, URL_PATTERN, SERVLET_CLASS,
					PARAM_NAME, PARAM_VALUE }));
		
		@Override
		public void startElement(String uri, String localName,
				String qName, Attributes attributes)
				throws SAXException {

			if (tagsToGrab.contains(qName)) {
				grabText = true;
			}
		}

		@Override
		public void endElement(String uri, String localName,
				@NotNull String qName) throws SAXException {
			
			switch (qName) {
				case SERVLET_NAME:  servletName  = getBuilderText(); break;
				case URL_PATTERN:   urlPattern   = getBuilderText(); break;
				case SERVLET_CLASS: servletClass = getBuilderText(); break;
				case SERVLET_MAPPING:
                    if (servletName != null && urlPattern != null) {
					    mappings.add(new UrlPatternMapping(servletName, urlPattern));
                    }
					break;
				case SERVLET:
					if (servletName != null && servletClass != null) {
						servlets.add(new ClassMapping(servletName, servletClass, contextConfigLocation));
						contextConfigLocation = null;
					}
					break;
				case PARAM_VALUE: 
					if (getContextConfigLocation) {
						contextConfigLocation = getBuilderText();
						getContextConfigLocation = false;
					}
					break;
				case PARAM_NAME:
					if (CONTEXT_CONFIG_LOCATION.equals(getBuilderText())) {
						getContextConfigLocation = true;
					}
					break;
			}
		}

		@Override
		public void characters(char ch[], int start, int length)
				throws SAXException {
			if (grabText) {
				builder.append(ch, start, length);
			}
		}
		
		@NotNull
        private String getBuilderText() {
			String returnValue = builder.toString();
			builder.setLength(0);
			grabText = false;
			return returnValue;
		}
	}
}
