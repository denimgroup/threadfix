////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2015 Denim Group, Ltd.
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

import com.denimgroup.threadfix.framework.engine.AbstractEndpoint;
import com.denimgroup.threadfix.framework.engine.CodePoint;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.*;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.CollectionUtils.map;
import static com.denimgroup.threadfix.CollectionUtils.set;

class JSPEndpoint extends AbstractEndpoint {

    @Nonnull
	private final String dynamicPath, staticPath;

    @Nonnull
	private final Set<String> parameters = set(), methods;

	@Nonnull
    private final Map<String, Integer> paramToLineMap;

	@Nonnull
    private final Map<Integer, List<String>> parameterMap;
	
	public JSPEndpoint(@Nonnull String staticPath,
                       @Nonnull String dynamicPath,
                       @Nonnull Set<String> methods,
			           @Nonnull Map<Integer, List<String>> parameterMap) {
		this.methods = methods;
		this.staticPath = staticPath;
		this.dynamicPath = dynamicPath;
		this.parameterMap = parameterMap;
		
        for (List<String> value : parameterMap.values()) {
            parameters.addAll(value);
        }

		this.paramToLineMap = getParamToLineMap(parameterMap);
	}

	@Nonnull
    private Map<String, Integer> getParamToLineMap(
			Map<Integer, List<String>> parameterMap) {
		Map<String, Integer> paramMap = map();
		
		for (String parameter : parameters) {
			paramMap.put(parameter, getFirstLineNumber(parameter, parameterMap));
		}
		
		return paramMap;
	}
	
	private Integer getFirstLineNumber(@Nonnull String parameterName,
			@Nonnull Map<Integer, List<String>> parameterMap) {
		Integer returnValue = Integer.MAX_VALUE;
		
        for (Map.Entry<Integer, List<String>> entry : parameterMap.entrySet()) {
            if (entry.getKey() < returnValue &&
                    entry.getValue() != null &&
                    entry.getValue().contains(parameterName)) {
                returnValue = entry.getKey();
            }
        }

		if (returnValue == Integer.MAX_VALUE) {
			returnValue = 1; // This way even if no parameter is found a marker can be created for the file
		}
		
		return returnValue;
	}
	
	// TODO improve
    @Nullable
    String getParameterName(@Nonnull Iterable<CodePoint> codePoints) {
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

	@Nonnull
    @Override
	public Set<String> getParameters() {
		return parameters;
	}
	
	@Nonnull
    @Override
	public String getUrlPath() {
		return dynamicPath;
	}

	@Nonnull
    @Override
	public Set<String> getHttpMethods() {
		return methods;
	}

	@Override
	public boolean matchesLineNumber(int lineNumber) {
		return true; // JSPs aren't controller-based, so the whole page is the endpoint
	}

	@Nonnull
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
        Integer value = paramToLineMap.get(parameter);
        if (value == null) {
            return 0;
        } else {
		    return value;
        }
	}


    @Nonnull
    @Override
    protected List<String> getLintLine() {
        return list();
    }
}
