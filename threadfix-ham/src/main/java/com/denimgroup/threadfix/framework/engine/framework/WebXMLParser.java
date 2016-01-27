////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2016 Denim Group, Ltd.
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
package com.denimgroup.threadfix.framework.engine.framework;

import com.denimgroup.threadfix.framework.engine.ProjectDirectory;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import java.io.File;
import java.io.IOException;
import java.util.*;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.CollectionUtils.map;
import static com.denimgroup.threadfix.CollectionUtils.set;

class WebXMLParser {

    private static final SanitizedLogger log = new SanitizedLogger("FrameworkCalculator");

    private WebXMLParser() {
		// intentionally inaccessible
	}
	
	@Nullable
    public static ServletMappings getServletMappings(@Nonnull File file,
			ProjectDirectory projectDirectory) {
		ServletParser parser = new WebXMLParser.ServletParser();

		try {
			SAXParserFactory factory = SAXParserFactory.newInstance();
			SAXParser saxParser = factory.newSAXParser();

			saxParser.parse(file, parser);
		} catch (IOException e) {
			log.warn("Encountered exception while parsing mappings.", e);
		} catch (SAXException e) {
			log.warn("Encountered exception while parsing mappings.", e);
		} catch (ParserConfigurationException e) {
			log.warn("Encountered exception while parsing mappings.", e);
		}

		return new ServletMappings(parser.mappings,
                parser.servlets,
                projectDirectory,
                parser.contextParams);
	}
	
	// this class is private static so that it doesn't share state with its parent class
	// but is only accessible to this class.
	private static class ServletParser extends DefaultHandler {
		
		@Nonnull
        List<ClassMapping> servlets = list();
		@Nonnull
        List<UrlPatternMapping> mappings = list();
        @Nonnull
        Map<String, String> contextParams = map();
		
		@Nullable
        String servletName = null, urlPattern = null,
                servletClass = null,
                contextConfigLocation = null,
                contextClass = null;
		@Nonnull
        StringBuilder builder = new StringBuilder();
		
		boolean getContextConfigLocation = false,
                getContextClass = false,
				grabText = false;

		private static final String
			SERVLET_MAPPING = "servlet-mapping",
			SERVLET = "servlet",
			SERVLET_NAME = "servlet-name",
			URL_PATTERN = "url-pattern",
			SERVLET_CLASS = "servlet-class",
			PARAM_NAME = "param-name",
			PARAM_VALUE = "param-value",
			CONTEXT_CONFIG_LOCATION = "contextConfigLocation",
            CONTEXT_CLASS = "contextClass",
            CONTEXT_PARAM = "context-param";

		@Nonnull
        private static Set<String> tagsToGrab = set(
				SERVLET_NAME, URL_PATTERN, SERVLET_CLASS,
						PARAM_NAME, PARAM_VALUE);
		
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
				@Nonnull String qName) throws SAXException {

			if (qName.equals(SERVLET_NAME)) {
				servletName = getBuilderText();
			} else if (qName.equals(URL_PATTERN)) {
				urlPattern = getBuilderText();
			} else if (qName.equals(SERVLET_CLASS)) {
				servletClass = getBuilderText();
			} else if (qName.equals(SERVLET_MAPPING)) {
				if (servletName != null && urlPattern != null) {
					mappings.add(new UrlPatternMapping(servletName, urlPattern));
				}

			} else if (qName.equals(SERVLET)) {
				if (servletName != null && servletClass != null) {
					servlets.add(new ClassMapping(servletName, servletClass, contextConfigLocation, contextClass));
					contextConfigLocation = null;
					contextClass = null;
				}

			} else if (qName.equals(CONTEXT_PARAM)) {
				if (contextConfigLocation != null) {
					contextParams.put(CONTEXT_CONFIG_LOCATION, contextConfigLocation);
					contextConfigLocation = null;
				}
				if (contextClass != null) {
					contextParams.put(CONTEXT_CLASS, contextClass);
					contextClass = null;
				}

			} else if (qName.equals(PARAM_VALUE)) {
				if (getContextConfigLocation) {
					contextConfigLocation = getBuilderText();
					getContextConfigLocation = false;
				} else if (getContextClass) {
					contextClass = getBuilderText();
					getContextClass = false;
				}

			} else if (qName.equals(PARAM_NAME)) {
				String text = getBuilderText();
				if (CONTEXT_CONFIG_LOCATION.equals(text)) {
					getContextConfigLocation = true;
				} else if (CONTEXT_CLASS.equals(text)) {
					getContextClass = true;
				}

			} else {
			}
            grabText = false;
		}

		@Override
		public void characters(char ch[], int start, int length)
				throws SAXException {
			if (grabText) {
				builder.append(ch, start, length);
			}
		}
		
		@Nonnull
        private String getBuilderText() {
			String returnValue = builder.toString();
			builder.setLength(0);
			grabText = false;
			return returnValue;
		}
	}
}
