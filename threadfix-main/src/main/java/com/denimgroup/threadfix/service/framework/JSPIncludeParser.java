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
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.io.StreamTokenizer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

import com.denimgroup.threadfix.service.SanitizedLogger;

public class JSPIncludeParser {
	
	private enum State {
		START, JSP, COLON, INCLUDE, PAGE, EQUALS
	}
	
	private static final Pattern slashPattern = Pattern.compile("[\\\\/]");
	
	private static final SanitizedLogger log = new SanitizedLogger("JSPIncludeParser");
	
	private JSPIncludeParser(){}
	
	// TODO modularize / abstract out tokenizer functionality. 
	// a wrapper that works like SAX parsing would be cool
	public static List<File> getIncludedFiles(File inputFile) {
		List<File> returnFiles = new ArrayList<>();
		
		State currentState = State.START;
		
		// contains() is used instead of endsWith() so we can accept nonstandard jsp extensions like jspf
		if (inputFile != null && 
				inputFile.exists() && 
				inputFile.isFile() && 
				inputFile.getName().contains(".jsp")) {
			Reader reader = null;
			
			try {
				reader = new FileReader(inputFile);
			
				StreamTokenizer tokenizer = new StreamTokenizer(reader);
				
				while (tokenizer.nextToken() != StreamTokenizer.TT_EOF) {
					
					switch (currentState) {
						case START:
							if (tokenizer.sval != null && tokenizer.sval.equals("jsp")) {
								currentState = State.JSP;
							}
							break;
						case JSP:
							if (tokenizer.ttype == ':') {
								currentState = State.COLON;
							}
							break;
						case COLON:
							if (tokenizer.sval != null && tokenizer.sval.equals("include")) {
								currentState = State.INCLUDE;
							}
							break;
						case INCLUDE:
							if (tokenizer.sval != null && tokenizer.sval.equals("page")) {
								currentState = State.PAGE;
							} else if (tokenizer.ttype == '<') {
								// if we hit another start tag let's head back to the start
								currentState = State.START;
							}
							break;
						case PAGE:
							if (tokenizer.ttype == '=') {
								currentState = State.EQUALS;
							} else {
								currentState = State.START;
							}
							break;
						case EQUALS:
							if (tokenizer.ttype == '"' && tokenizer.sval != null) {
								returnFiles.add(getRelativeFile(tokenizer.sval, inputFile));
								currentState = State.START;
							} else {
								currentState = State.START;
							}
							break;
						default:
							break;
					}
				}
				
			} catch (FileNotFoundException e) {
				// shouldn't happen, we check to make sure it exists
				log.error("Encountered FileNotFoundException while looking for nested JSPs", e);
			} catch (IOException e) {
				log.warn("Encountered IOException while tokenizing file.", e);
			} finally {
				if (reader != null) {
					try {
						reader.close();
					} catch (IOException e) {
						log.error("IOException encountered while trying to close the FileReader.");
					}
				}
			}
		}
		
		return returnFiles;
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
