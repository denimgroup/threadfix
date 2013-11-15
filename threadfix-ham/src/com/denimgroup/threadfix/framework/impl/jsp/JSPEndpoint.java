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
package com.denimgroup.threadfix.framework.impl.jsp;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.denimgroup.threadfix.framework.engine.AbstractEndpoint;
import com.denimgroup.threadfix.framework.engine.CodePoint;

public class JSPEndpoint extends AbstractEndpoint {
	
	private final String dynamicPath, staticPath;
	private final Set<String> parameters = new HashSet<>(), methods;
	private final Map<String, Integer> paramToLineMap;
	private final Map<Integer, List<String>> parameterMap;
	
	public JSPEndpoint(String staticPath,
			String dynamicPath,
			Set<String> methods,
			Map<Integer, List<String>> parameterMap) {
		this.methods = methods;
		this.staticPath = staticPath;
		this.dynamicPath = dynamicPath;
		this.parameterMap = parameterMap;
		
		if (parameterMap != null) {
			for (List<String> value : parameterMap.values()) {
				parameters.addAll(value);
			}
		}
		
		this.paramToLineMap = getParamToLineMap(parameterMap);
	}

	private Map<String, Integer> getParamToLineMap(
			Map<Integer, List<String>> parameterMap) {
		Map<String, Integer> paramMap = new HashMap<>();
		
		for (String parameter : parameters) {
			paramMap.put(parameter, getFirstLineNumber(parameter, parameterMap));
		}
		
		return paramMap;
	}
	
	private Integer getFirstLineNumber(String parameterName,
			Map<Integer, List<String>> parameterMap) {
		Integer returnValue = Integer.MAX_VALUE;
		
		if (parameterMap != null && parameterName != null) {
			for (Integer integer : parameterMap.keySet()) {
				if (integer < returnValue &&
						parameterMap.get(integer) != null &&
						parameterMap.get(integer).contains(parameterName)) {
					returnValue = integer;
				}
			}
		}
		
		if (returnValue == Integer.MAX_VALUE) {
			returnValue = 1; // This way even if no parameter is found a marker can be created for the file
		}
		
		return returnValue;
	}
	
	// TODO improve
	String getParameterName(Iterable<CodePoint> codePoints) {
		String parameter = null;
		
		for (CodePoint codePoint : codePoints) {
			List<String> possibleParameters = parameterMap.get(codePoint.getLineNumber());
			
			if (possibleParameters != null && possibleParameters.size() == 1) {
				parameter = possibleParameters.get(0);
				break;
			}
		}
		
		return parameter;
	}

	@Override
	public Set<String> getParameters() {
		return parameters;
	}
	
	@Override
	public String getUrlPath() {
		return dynamicPath;
	}

	@Override
	public Set<String> getHttpMethods() {
		return methods;
	}

	@Override
	public boolean matchesLineNumber(int lineNumber) {
		return true; // JSPs aren't controller-based, so the whole page is the endpoint
	}

	@Override
	public String getFilePath() {
		return staticPath;
	}

	@Override
	public int getStartingLineNumber() {
		return -1; // JSPs aren't controller-based, so the whole page is the endpoint
	}

	@Override
	public int getLineNumberForParameter(String parameter) {
		return paramToLineMap.get(parameter);
	}
	
	

}
