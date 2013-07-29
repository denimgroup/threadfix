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
import java.util.HashSet;
import java.util.List;
import java.util.Set;

// TODO recognize String variables
// TODO support * values:
// from Spring documentation: Ant-style path patterns are supported (e.g. "/myPath/*.do").
public class SpringControllerEndpointParser implements EventBasedTokenizer {
	
	private Set<SpringControllerEndpoint> endpoints = new HashSet<>();
	private State state = State.START;
	private int startLineNumber = 0, curlyBraceCount = 0;
	private boolean inClass = false;
	private String classEndpoint = null, currentMapping = null, rootFilePath = null;
	private List<String> classMethods = new ArrayList<>(), methodMethods = new ArrayList<>();

	enum State {
		START, ARROBA, REQUEST_MAPPING, VALUE, METHOD, METHOD_MULTI_VALUE, ANNOTATION_END, METHOD_BODY;
	}
	
	public static Set<SpringControllerEndpoint> parse(File file) {
		SpringControllerEndpointParser parser = new SpringControllerEndpointParser(file.getAbsolutePath());
		EventBasedTokenizerRunner.run(file, parser);
		return parser.endpoints;
	}
	
	private SpringControllerEndpointParser(String rootFilePath) {
		this.rootFilePath = rootFilePath;
	}
	
	@Override
	public void processToken(int type, int lineNumber, String stringValue) {
		switch(state) {
		case START: 
			if (type == '@') {
				state = State.ARROBA;
			} else if (stringValue != null && stringValue.equals("class")) {
				inClass = true;
			}
			break;
		case ARROBA:
			if (stringValue != null && stringValue.equals("RequestMapping")) {
				state = State.REQUEST_MAPPING;
			} else {
				state = State.START;
			}
			break;
		case REQUEST_MAPPING:
			if (stringValue != null && stringValue.equals("value")) {
				state = State.VALUE;
			} else if (stringValue != null && stringValue.equals("method")) {
				state = State.METHOD;
			} else if (type == '"') {
				// If it immediately starts with a quoted value, use it
				if (inClass) {
					currentMapping = stringValue;
					startLineNumber = lineNumber;
					state = State.ANNOTATION_END;
				} else {
					classEndpoint = stringValue;
					state = State.START;
				}
			} else if (type == ')'){
				state = State.ANNOTATION_END;
			}
			break;
		case VALUE:
			if (stringValue != null) {
				if (inClass) {
					currentMapping = stringValue;
					startLineNumber = lineNumber;
				} else {
					classEndpoint = stringValue;
				}
				state = State.REQUEST_MAPPING;
			}
			break;
		case METHOD:
			if (stringValue != null) {
				if (inClass) {
					methodMethods.add(stringValue);
				} else {
					classMethods.add(stringValue);
				}
				state = State.REQUEST_MAPPING;
			} else if (type == '{'){
				state = State.METHOD_MULTI_VALUE;
			}
			break;
		case METHOD_MULTI_VALUE:
			if (stringValue != null) {
				if (inClass) {
					methodMethods.add(stringValue);
				} else {
					classMethods.add(stringValue);
				}
			} else if (type == '}') {
				state = State.REQUEST_MAPPING;
			}
			break;
		case ANNOTATION_END:
			if (inClass) {
				state = State.METHOD_BODY;
			} else {
				state = State.START;
			}
			break;
		case METHOD_BODY:
			if (type == '{') {
				curlyBraceCount += 1;
				
			} else if (type == '}') {
				if (curlyBraceCount == 1) {
					addEndpoint(lineNumber);
					state = State.START;
				} else {
					curlyBraceCount -= 1;
				}
			}
			break;
		}
	}
	
	private void addEndpoint(int endLineNumber) {
		if (classEndpoint != null) {
			currentMapping = classEndpoint + currentMapping;
		}
		
		// It's ok to add a default method here because we must be past the class-level annotation
		if (classMethods.isEmpty()) {
			classMethods.add("RequestMethod.GET");
		}
		
		if (methodMethods == null || methodMethods.isEmpty()) {
			methodMethods.addAll(classMethods);
		}
		
		endpoints.add(new SpringControllerEndpoint(rootFilePath, currentMapping, 
				methodMethods, startLineNumber, endLineNumber));
		currentMapping = null;
		methodMethods = new ArrayList<>();
		startLineNumber = -1;
		curlyBraceCount = 0;
	}
	
}
