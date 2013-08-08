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

import java.util.List;
import java.util.regex.Pattern;

import com.denimgroup.threadfix.data.entities.DataFlowElement;
import com.denimgroup.threadfix.data.entities.Finding;

public class SpringModelParameterParser implements ParameterParser {
	
	// So we only compile once
	private static final Pattern MODEL_OBJECT_PATTERN = Pattern.compile("([a-zA-Z0-9_]+), BindingResult");
	
	/**
	 * Examines the data flow to try to find Spring parameters.
	 * 
	 * This method takes advantage of a few assumptions:
	 * 	1. The flow will follow only one parameter.
	 *  2. The first element in the flow will be the Spring controller method call
	 *  3. There are no intermediate objects: the first accessor call will be a string.
	 *  
	 *  TODO handle owner.pet.name and similar cases
	 *  TODO add requestvariable
	 * 
	 * @param dataFlowElements
	 * @return
	 */
	public String parse(Finding finding) {
		String parameter = null;
		
		if (finding != null && finding.getDataFlowElements() != null && 
				!finding.getDataFlowElements().isEmpty()) {
			
			parameter = attemptModelParsing(finding.getDataFlowElements());
			if (parameter == null) {
				parameter = attemptPathVariableParsing(finding.getDataFlowElements().get(0));
			}
			
		}
		
		if (parameter == null && finding != null && finding.getSurfaceLocation() != null) {
			parameter = finding.getSurfaceLocation().getParameter();
		}
		
		return parameter;
	}
	
	private String attemptPathVariableParsing(DataFlowElement dataFlowElement) {
		String parameter = null;
		
		// try for @PathVariable("ownerId") int ownerId
		parameter = RegexUtils.getRegexResult(dataFlowElement.getLineText(), "@PathVariable\\(\"([a-zA-Z0-9]+)\"\\)");
		
		if (parameter != null) {
			// try for @PathVariable String ownerName
			parameter = RegexUtils.getRegexResult(dataFlowElement.getLineText(), "@PathVariable [^ ]+ ([^,]+)");
		}
		
		return parameter;
	}

	private String attemptModelParsing(List<DataFlowElement> dataFlowElements) {
		
		String parameter = null;
		
		String modelObject = getModelObject(dataFlowElements.get(0));
		
		if (modelObject != null) {
			for (DataFlowElement element : dataFlowElements) {
				if (element.getLineText() != null) {
					parameter = getParameter(element.getLineText(), modelObject);
					if (parameter != null) {
						break;
					}
				}
			}
		}
		
		return parameter;
	}
	
	private String getModelObject(DataFlowElement element) {
		return RegexUtils.getRegexResult(element.getLineText(), MODEL_OBJECT_PATTERN);
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
