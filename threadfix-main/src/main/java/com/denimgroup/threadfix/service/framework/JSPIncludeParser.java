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
package com.denimgroup.threadfix.service.framework;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

import com.denimgroup.threadfix.service.SanitizedLogger;

public class JSPIncludeParser implements EventBasedTokenizer {
	
	public static void main(String[] args) {
		File file = new File("C:\\test\\projects\\spring-petclinic\\src\\main\\" +
				"webapp\\WEB-INF\\jsp\\owners\\findOwners.jsp");
		
		System.out.println(JSPIncludeParser.parse(file));
	}
	
	private State currentState = State.START;
	private List<File> returnFiles = new ArrayList<File>();
	private File inputFile;
	
	private enum State {
		START, JSP, COLON, INCLUDE, PAGE, EQUALS
	}
	
	private static final Pattern slashPattern = Pattern.compile("[\\\\/]");
	private static final SanitizedLogger log = new SanitizedLogger("JSPIncludeParser");
	
	private JSPIncludeParser(File file) {
		this.inputFile = file;
	}
	
	public static List<File> parse(File file) {
		JSPIncludeParser parser = new JSPIncludeParser(file);
		EventBasedTokenizerRunner.run(file, parser);
		return parser.returnFiles;
	}

	@Override
	public void processToken(int type, int lineNumber, String stringValue) {
		switch (currentState) {
			case START:
				if (stringValue != null && stringValue.equals("jsp")) {
					currentState = State.JSP;
				}
				break;
			case JSP:
				if (type == ':') {
					currentState = State.COLON;
				}
				break;
			case COLON:
				if (stringValue != null && stringValue.equals("include")) {
					currentState = State.INCLUDE;
				}
				break;
			case INCLUDE:
				if (stringValue != null && stringValue.equals("page")) {
					currentState = State.PAGE;
				} else if (type == '<') {
					// if we hit another start tag let's head back to the start
					currentState = State.START;
				}
				break;
			case PAGE:
				if (type == '=') {
					currentState = State.EQUALS;
				} else {
					currentState = State.START;
				}
				break;
			case EQUALS:
				if (type == '"' && stringValue != null) {
					returnFiles.add(getRelativeFile(stringValue, inputFile));
					currentState = State.START;
				} else {
					currentState = State.START;
				}
				break;
			default:
				break;
		}
	}
	
	private static File getRelativeFile(String sval, File inputFile) {
		File returnFile = null;
		
		List<String> 
			inputFilePathSegments = new ArrayList<>(Arrays.asList(slashPattern.split(inputFile.getParent()))),
			svalPathSegments = new ArrayList<>(Arrays.asList(slashPattern.split(sval)));
		
		if (svalPathSegments.size() > 0) {
			for (String string : svalPathSegments) {
				if ("..".equals(string)) {
					inputFilePathSegments.remove(inputFilePathSegments.size() - 1);
				} else if (string != null) {
					inputFilePathSegments.add(string);
				}
			}
		}
		
		StringBuilder builder = new StringBuilder();
		for (String segment : inputFilePathSegments) {
			builder.append(segment);
			builder.append(File.separator);
		}
		
		String resultingString = builder.substring(0, builder.length() - 1);
		
		returnFile = new File(resultingString);
		
		if (returnFile.exists() && returnFile.isFile()) {
			log.info("Located included JSP file " + returnFile.getName());
		} else {
			log.info("Unable to locate included JSP file.");
		}
		
		return returnFile;
	}
}
