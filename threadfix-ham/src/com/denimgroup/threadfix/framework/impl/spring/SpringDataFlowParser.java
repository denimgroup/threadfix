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
package com.denimgroup.threadfix.framework.impl.spring;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

import com.denimgroup.threadfix.framework.beans.BeanField;
import com.denimgroup.threadfix.framework.beans.CodePoint;
import com.denimgroup.threadfix.framework.beans.ParameterParser;
import com.denimgroup.threadfix.framework.engine.EndpointQuery;
import com.denimgroup.threadfix.framework.util.RegexUtils;

public class SpringDataFlowParser implements ParameterParser {
	
	// So we only compile these patterns once
	private static final Pattern
		ENTITY_TYPE_PATTERN      = Pattern.compile("([a-zA-Z0-9_]+) [^ ]+, ?BindingResult"),
		ENTITY_OBJECT_PATTERN    = Pattern.compile("([a-zA-Z0-9_]+), ?BindingResult"),
		PATH_VARIABLE_WITH_PARAM = Pattern.compile("@PathVariable\\(\"([a-zA-Z0-9]+)\"\\)"),
		PATH_VARIABLE_NO_PARAM   = Pattern.compile("@PathVariable [^ ]+ ([^,\\)]+)"),
		REQUEST_PARAM_WITH_PARAM = Pattern.compile("@RequestParam\\(\"([a-zA-Z0-9]+)\"\\)"),
		REQUEST_PARAM_NO_PARAM   = Pattern.compile("@RequestParam [^ ]+ ([^,\\)]+)");
	
	private final SpringEntityMappings mappings;
	
	public SpringDataFlowParser(SpringEntityMappings mappings) {
		this.mappings = mappings;
	}
	
	/**
	 * Examines the data flow to try to find Spring parameters.
	 * 
	 * This method takes advantage of a few assumptions:
	 * 	1. The flow will follow only one parameter.
	 *  2. The first element in the flow will be the Spring controller method call
	 * 
	 *  TODO handle owner.pet.name and similar cases
	 * 
	 * @param dataFlowElements
	 * @return
	 */
	@Override
	public String parse(EndpointQuery query) {
		
		String parameter = null;
		
		if (query != null && query.getCodePoints() != null &&
				!query.getCodePoints().isEmpty()) {
			
			List<String> lines = getLines(query.getCodePoints());
			
			if (mappings == null || mappings.isEmpty()) {
				parameter = attemptModelParsingNoMappings(lines);
			} else {
				parameter = attemptModelParsingWithMappings(lines);
			}
			if (parameter == null || parameter.isEmpty()) {
				parameter = attemptPathVariableParsing(lines);
			}
		}
		
		if (parameter == null && query != null) {
			parameter = query.getParameter();
		}
		
		return parameter;
	}
	
	private List<String> getLines(List<CodePoint> codePoints) {
		List<String> returnList = new ArrayList<>(codePoints.size());
		
		for (CodePoint element : codePoints) {
			if (element != null && element.getLineText() != null) {
				returnList.add(element.getLineText());
			}
		}
		
		return returnList;
	}

	// TODO move to a system that supports more than one variable
	private String attemptPathVariableParsing(List<String> lines) {
		
		String parameter = null;
		
		if (lines != null && !lines.isEmpty()) {
			String elementText = lines.get(0);
		
			// try for @PathVariable("ownerId") int ownerId
			parameter = RegexUtils.getRegexResult(elementText, PATH_VARIABLE_WITH_PARAM);
			
			if (parameter == null) {
				// try for @PathVariable String ownerName
				parameter = RegexUtils.getRegexResult(elementText, PATH_VARIABLE_NO_PARAM);
			}
			
			if (parameter == null) {
				// try for @RequestParam("ownerName") String ownerName
				parameter = RegexUtils.getRegexResult(elementText, REQUEST_PARAM_WITH_PARAM);
			}
			
			if (parameter == null) {
				// try for @RequestParam String ownerName
				parameter = RegexUtils.getRegexResult(elementText, REQUEST_PARAM_NO_PARAM);
			}
		}
		
		return parameter;
	}

	private String attemptModelParsingNoMappings(List<String> lines) {
		
		String parameter = null;
		
		if (lines != null && !lines.isEmpty()) {
			String modelObject = getModelObject(lines.get(0));
			
			if (modelObject != null) {
				for (String elementText : lines) {
					if (elementText != null) {
						parameter = getParameter(elementText, modelObject);
						
						if (parameter != null) {
							break;
						}
					}
				}
			}
		}
		
		return parameter;
	}
	
	private String attemptModelParsingWithMappings(List<String> lines) {
		String result = null;
		
		if (lines != null && !lines.isEmpty()) {
			String modelObject = getModelObject(lines.get(0));
			String initialType = getModelObjectType(lines.get(0));
			
			BeanField beanField = new BeanField(initialType, modelObject);
			
			List<BeanField> fieldChain = new ArrayList<>(Arrays.asList(beanField));
					
			if (modelObject != null) {
				for (String elementText : lines) {
					if (elementText != null) {
						List<BeanField> beanFields = getParameterWithEntityData(elementText,
								fieldChain.get(fieldChain.size() - 1));
						
						if (beanFields != null && beanFields.size() > 1) {
							beanFields.remove(0);
							fieldChain.addAll(beanFields);
							beanField = fieldChain.get(fieldChain.size() - 1);
						}
						
						if (beanField.isPrimitiveType()) {
							break;
						}
					}
				}
			}
	
			result = buildStringFromFieldChain(fieldChain);
		}
		
		return result;
	}
	
	private String buildStringFromFieldChain(List<BeanField> fieldChain) {
		StringBuilder parameterChainBuilder = new StringBuilder();
		
		if (fieldChain.size() > 1) {
			fieldChain.remove(0);
			for (BeanField field : fieldChain) {
				parameterChainBuilder.append(field.getParameterKey()).append('.');
			}
			parameterChainBuilder.setLength(parameterChainBuilder.length() - 1);
		}
		
		return parameterChainBuilder.toString();
	}
	
	private String getModelObject(String elementText) {
		return RegexUtils.getRegexResult(elementText, ENTITY_OBJECT_PATTERN);
	}
	
	private String getModelObjectType(String elementText) {
		return RegexUtils.getRegexResult(elementText, ENTITY_TYPE_PATTERN);
	}
	
	private List<BeanField> getParameterWithEntityData(String line, BeanField beanField) {
		List<String> methodCalls = RegexUtils.getRegexResults(line,
				Pattern.compile(beanField.getParameterKey() + "(\\.get[^\\(]+\\(\\))+"));
		
		List<BeanField> returnField = new ArrayList<>();
		
		if (methodCalls != null && !methodCalls.isEmpty()) {
			returnField = mappings.getFieldsFromMethodCalls(methodCalls.get(0), beanField);
		}
		
		return returnField;
	}

	private String getParameter(String line, String modelObject) {
		String methodCall = RegexUtils.getRegexResult(line, "(" + modelObject + "\\.[a-zA-Z0-9]+)");
		
		String parameterName = null;
		
		if (methodCall != null) {
			parameterName = getParameterFromBeanAccessor(modelObject, methodCall);
		}
		
		return parameterName;
	}

	private String getParameterFromBeanAccessor(String modelObject,
			String methodCall) {
		
		String propertyName = null;
		
		if (methodCall.startsWith(modelObject + ".get")) {
			propertyName = methodCall.substring(modelObject.length() + 4);
			propertyName = propertyName.substring(0,1).toLowerCase() + propertyName.substring(1);
		}
		
		return propertyName;
	}
	
}
