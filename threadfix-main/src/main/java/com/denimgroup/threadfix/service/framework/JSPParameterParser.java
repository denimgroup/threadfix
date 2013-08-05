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
import java.io.StreamTokenizer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


/**
 * @author mcollins
 * 
 * TODO restrict to parameters found inside <% %> blocks. Add to state machine
 * TODO handle session attributes?
 *
 */
public class JSPParameterParser implements EventBasedTokenizer {
	
//	private Map<Integer, String> lineNumberToParameterMap = new HashMap<>();
	private Map<String, List<Integer>> parameterToLineNumbersMap = new HashMap<>();
	private Map<String, String> 
		variableToParametersMap = new HashMap<>(),
		stringsTable = new HashMap<>();
	
	private static final String REQUEST_GET_PARAMETER = "request.getParameter", STRING = "String";
	
	private State state = State.START;
	private PageState pageState = PageState.START;
	
	private String varName = null;
	
	private JSPParameterParser() {}
	
	private enum State {
		START, STRING, VAR_NAME, EQUALS, GET_PARAMETER, NO_VARIABLE, ADDED_TO_STRINGS_TABLE
	}
	
	private enum PageState {
		START, OPEN_ANGLE_BRACKET, IN_JSP, PERCENTAGE
	}
	
	public static JSPParameterParser parse(File file) {
		JSPParameterParser parser = new JSPParameterParser();
		System.out.println(file.getAbsolutePath());
		EventBasedTokenizerRunner.run(file, parser);
		return parser;
	}
	
	public Map<String, List<Integer>> getParameterMap() {
		return parameterToLineNumbersMap;
	}
	
	public Map<String, String> getVariableToParameterMap() {
		return variableToParametersMap;
	}

	@Override
	public void processToken(int type, int lineNumber, String stringValue) {
		switch (pageState) {
			case START:
				if (type == '<') {
					pageState = PageState.OPEN_ANGLE_BRACKET;
				}
				break;
			case OPEN_ANGLE_BRACKET:
				if (type == '%') {
					pageState = PageState.IN_JSP;
					System.out.println("Going in at line " + lineNumber);
				} else if (type != '<'){
					pageState = PageState.START;
				}
				break;
			case IN_JSP:
				if (type == '%') {
					pageState = PageState.PERCENTAGE;
				} else {
					parseParameters(type, lineNumber, stringValue);
				}
				break;
			case PERCENTAGE:
				if (type == '>') {
					pageState = PageState.START;
					System.out.println("Exiting at line " + lineNumber);
				} else {
					pageState = PageState.IN_JSP;
					parseParameters(type, lineNumber, stringValue);
				}
				break;
		}
		
	}
	
	public void parseParameters(int type, int lineNumber, String stringValue) {
		switch (state) {
		case START:
			if (stringValue != null && stringValue.equals(REQUEST_GET_PARAMETER)) {
				state = State.NO_VARIABLE;
			} else if (stringValue != null && stringValue.equals(STRING)) {
				state = State.STRING;
			} else if (type == StreamTokenizer.TT_WORD){
				checkForParam(stringValue, lineNumber);
			}
			break;
		case STRING:
			if (stringValue != null) {
				varName = stringValue;
				state = State.VAR_NAME;
			}
			break;
		case VAR_NAME:
			if (!isSemicolonOrComma(type) && type == EQUALS) {
				state = State.EQUALS;
			}
			break;
		case EQUALS:
			if (!isSemicolonOrComma(type)) {
				if (stringValue != null && stringValue.equals(REQUEST_GET_PARAMETER)) {
					state = State.GET_PARAMETER;
				} else if (type == DOUBLE_QUOTE) {
					stringsTable.put(varName, stringValue);
					state = State.ADDED_TO_STRINGS_TABLE;
				}
			}
			break;
		case GET_PARAMETER:
			if (!isSemicolonOrComma(type)) {
				if (type == DOUBLE_QUOTE) {
					addVariableEntry(stringValue, lineNumber);
					state = State.START;
				} else if (type == StreamTokenizer.TT_WORD && stringValue != null) {
					if (stringsTable.containsKey(stringValue)) {
						addVariableEntry(stringsTable.get(stringValue), lineNumber);
					}
					state = State.START;
				}
			}
			
			break;
		case NO_VARIABLE:
			if (stringValue != null) {
				parameterToLineNumbersMap.put(stringValue, new ArrayList<Integer>());
				parameterToLineNumbersMap.get(stringValue).add(lineNumber);
				state = State.START;
			}
			break;
		case ADDED_TO_STRINGS_TABLE:
			isSemicolonOrComma(type);
			break;
		}
	}
	
	private void addVariableEntry(String parameterName, int lineNumber) {
		variableToParametersMap.put(varName, parameterName);
		varName = null;
		parameterToLineNumbersMap.put(parameterName, new ArrayList<Integer>());
		parameterToLineNumbersMap.get(parameterName).add(lineNumber);
	}
	
	// Sets state and returns whether state was changed
	private boolean isSemicolonOrComma(int type) {
		if (type == COMMA) {
			state = State.STRING;
		} else if (type == SEMICOLON) {
			state = State.START;
		}
		
		return type == COMMA || type == SEMICOLON;
	}
	
	private void checkForParam(String string, int lineNumber) {
		if (string != null &&
				variableToParametersMap.get(string) != null &&
				parameterToLineNumbersMap.get(variableToParametersMap.get(string)) != null) {
			parameterToLineNumbersMap.get(variableToParametersMap.get(string)).add(lineNumber);
		}
	}

}
