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
	private Map<String, String> variableToParametersMap = new HashMap<>();
	
	private static final String REQUEST_GET_PARAMETER = "request.getParameter", STRING = "String";
	
	private State state = State.START;
	
	private String varName = null;
	
	private JSPParameterParser() {}
	
	private enum State {
		START, STRING, VAR_NAME, EQUALS, GET_PARAMETER, NO_VARIABLE
	}
	
	public static JSPParameterParser parse(File file) {
		JSPParameterParser parser = new JSPParameterParser();
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
			if (type == EQUALS) {
				state = State.EQUALS;
			} else if (type == COMMA) {
				state = State.STRING;
			} else if (type == SEMICOLON) {
				state = State.START;
			}
			break;
		case EQUALS:
			if (stringValue != null && stringValue.equals(REQUEST_GET_PARAMETER)) {
				state = State.GET_PARAMETER;
			} else if (type == COMMA) {
				state = State.STRING;
			} else if (type == SEMICOLON) {
				state = State.START;
			}
			break;
		case GET_PARAMETER:
			if (type == DOUBLE_QUOTE) {
				variableToParametersMap.put(varName, stringValue);
				varName = null;
				parameterToLineNumbersMap.put(stringValue, new ArrayList<Integer>());
				parameterToLineNumbersMap.get(stringValue).add(lineNumber);
				state = State.START;
			} else if (type == COMMA) {
				state = State.STRING;
			} else if (type == SEMICOLON) {
				state = State.START;
			} else if (stringValue != null) {
				/* TODO add parameter awareness so we can catch those cases.
				 * 
				 * for instance:
				 * 
				 * String test = "username";
				 * String username = request.getParameter(test);
				 */
				state = State.START;
			}
			
			break;
		case NO_VARIABLE:
			if (stringValue != null) {
				parameterToLineNumbersMap.put(stringValue, new ArrayList<Integer>());
				parameterToLineNumbersMap.get(stringValue).add(lineNumber);
				state = State.START;
			}
		}
	}
	
	private void checkForParam(String string, int lineNumber) {
		if (string != null &&
				variableToParametersMap.get(string) != null &&
				parameterToLineNumbersMap.get(variableToParametersMap.get(string)) != null) {
			parameterToLineNumbersMap.get(variableToParametersMap.get(string)).add(lineNumber);
		}
	}

}
