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

import java.util.List;
import java.util.regex.Pattern;

import com.denimgroup.threadfix.framework.beans.CodePoint;
import com.denimgroup.threadfix.framework.beans.ParameterParser;
import com.denimgroup.threadfix.framework.engine.EndpointQuery;
import com.denimgroup.threadfix.framework.enums.SourceCodeAccessLevel;
import com.denimgroup.threadfix.framework.util.RegexUtils;

public class JSPDataFlowParser implements ParameterParser {
	
	private final JSPMappings jspMappings;
	private final SourceCodeAccessLevel sourceCodeAccessLevel;
	
	private static final Pattern REQUEST_GET_PARAM_STRING_ASSIGN =
			Pattern.compile("^String [^=]+= .*request\\.getParameter\\(\"([^\"]+)\"\\)");
	
	public JSPDataFlowParser(JSPMappings jspMappings, SourceCodeAccessLevel sourceCodeAccessLevel) {
		this.jspMappings = jspMappings;
		this.sourceCodeAccessLevel = sourceCodeAccessLevel;
	}

	@Override
	public String parse(EndpointQuery query) {
		String parameter = null;
		
		if (query != null && query.getCodePoints() != null) {
			if (sourceCodeAccessLevel != SourceCodeAccessLevel.FULL) {
				parameter = parseWithSource(query);
			} else {
				parameter = parseNoSource(query);
			}
		}
		
		if (parameter == null && query != null) {
			parameter = query.getParameter();
		}
		
		return parameter;
	}
	
	private String parseNoSource(EndpointQuery query) {
		String parameter = null;
		
		for (CodePoint element : query.getCodePoints()) {
			if (element != null && element.getLineText() != null) {
				String test = RegexUtils.getRegexResult(element.getLineText(),
						REQUEST_GET_PARAM_STRING_ASSIGN);
				if (test != null) {
					parameter = test;
				}
			}
		}
	
		return parameter;
	}
	
	private String parseWithSource(EndpointQuery query) {
		String test = null;
		
		boolean missingMappings = false;
		
		if (jspMappings == null) {
			test = parseNoSource(query);
		} else {
			for (CodePoint codePoint : query.getCodePoints()) {
				if (jspMappings.getParameterMap(codePoint.getSourceFileName()) != null) {
					List<String> possibleParameters = jspMappings
							.getParameterMap(codePoint.getSourceFileName())
							.get(codePoint.getLineNumber());
					if (possibleParameters != null && possibleParameters.size() == 1) {
						test = possibleParameters.get(0);
						break;
					}
				} else {
					missingMappings = true;
				}
			}
		}
		
		// if we're missing some mappings and didn't get a result, do the dumb regex parsing
		if (missingMappings && test == null) {
			test = parseNoSource(query);
		}
		
		return test;
	}
	
}
