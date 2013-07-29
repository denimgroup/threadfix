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
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.denimgroup.threadfix.service.SanitizedLogger;

// TODO recognize String variables
// TODO support * values:
// from Spring documentation: Ant-style path patterns are supported (e.g. "/myPath/*.do").
public class SpringControllerEndpointParser {
	
	enum State {
		START, ARROBA, REQUEST_MAPPING, VALUE, METHOD, METHOD_CURLY, END_PAREN, END_CURLY;
	}
	
	private static final SanitizedLogger log = new SanitizedLogger("SpringControllerEndpointParser");
	
	private SpringControllerEndpointParser(){}
	
	public static Set<SpringControllerEndpoint> parseEndpoints(File file) {
		State state = State.START;
		int startLineNumber = 0, curlyBraceCount = 0;
		boolean inClass = false;
		String classEndpoint = null, currentMapping = null;
		List<String> classMethods = new ArrayList<>(), methodMethods = new ArrayList<>();
		
		Set<SpringControllerEndpoint> endpoints = new HashSet<>();
		
		if (file != null && file.exists() && file.isFile() && file.getName().endsWith(".java")) {
			Reader reader = null;
			
			try {
				reader = new FileReader(file);
			
				StreamTokenizer tokenizer = new StreamTokenizer(reader);
				tokenizer.slashSlashComments(true);
				tokenizer.slashStarComments(true);
				
				while (tokenizer.nextToken() != StreamTokenizer.TT_EOF) {
					switch(state) {
						case START: 
							if (tokenizer.ttype == '@') {
								state = State.ARROBA;
							} else if (tokenizer.sval != null && tokenizer.sval.equals("class")) {
								inClass = true;
							}
							break;
						case ARROBA:
							if (tokenizer.sval != null && tokenizer.sval.equals("RequestMapping")) {
								state = State.REQUEST_MAPPING;
							} else {
								state = State.START;
							}
							break;
						case REQUEST_MAPPING:
							if (tokenizer.sval != null && tokenizer.sval.equals("value")) {
								state = State.VALUE;
							} else if (tokenizer.sval != null && tokenizer.sval.equals("method")) {
								state = State.METHOD;
							} else if (tokenizer.ttype == '"') {
								// If it immediately starts with a quoted value, use it
								if (inClass) {
									currentMapping = tokenizer.sval;
									startLineNumber = tokenizer.lineno();
									state = State.END_PAREN;
								} else {
									classEndpoint = tokenizer.sval;
									state = State.START;
								}
							} else if (tokenizer.ttype == ')'){
								state = State.END_PAREN;
							}
							break;
						case VALUE:
							if (tokenizer.sval != null) {
								if (inClass) {
									currentMapping = tokenizer.sval;
									startLineNumber = tokenizer.lineno();
								} else {
									classEndpoint = tokenizer.sval;
								}
								state = State.REQUEST_MAPPING;
							}
							break;
						case METHOD:
							if (tokenizer.sval != null) {
								if (inClass) {
									methodMethods.add(tokenizer.sval);
								} else {
									classMethods.add(tokenizer.sval);
								}
								state = State.REQUEST_MAPPING;
							} else if (tokenizer.ttype == '{'){
								state = State.METHOD_CURLY;
							}
							break;
						case METHOD_CURLY:
							if (tokenizer.sval != null) {
								if (inClass) {
									methodMethods.add(tokenizer.sval);
								} else {
									classMethods.add(tokenizer.sval);
								}
							} else if (tokenizer.ttype == '}') {
								state = State.REQUEST_MAPPING;
							}
							break;
						case END_PAREN:
							if (inClass) {
								state = State.END_CURLY;
							} else {
								state = State.START;
							}
							break;
						case END_CURLY:
							if (tokenizer.ttype == '{') {
								curlyBraceCount += 1;
								
							} else if (tokenizer.ttype == '}') {
								if (curlyBraceCount == 1) {
									
									String filePath = file.getAbsolutePath();
									if (classEndpoint != null) {
										currentMapping = classEndpoint + currentMapping;
									}
									
									if (classMethods.isEmpty()) {
										classMethods.add("RequestMethod.GET");
									}
									
									if (methodMethods == null || methodMethods.isEmpty()) {
										methodMethods.addAll(classMethods);
									}
									
									endpoints.add(new SpringControllerEndpoint(filePath, currentMapping, 
											methodMethods, startLineNumber, tokenizer.lineno()));
									currentMapping = null;
									methodMethods = new ArrayList<>();
									startLineNumber = -1;
									curlyBraceCount = 0;
									state = State.START;
								} else {
									curlyBraceCount -= 1;
								}
							}
							break;
					}
				}
			} catch (FileNotFoundException e) {
				// shouldn't happen, we check to make sure it exists
				log.error("Encountered FileNotFoundException while looking for @Controllers", e);
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
		
		return endpoints;
	}
	
}
