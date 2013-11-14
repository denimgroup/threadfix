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

import com.denimgroup.threadfix.framework.engine.CodePoint;
import com.denimgroup.threadfix.framework.engine.ProjectConfig;
import com.denimgroup.threadfix.framework.engine.full.EndpointQuery;
import com.denimgroup.threadfix.framework.engine.parameter.ParameterParser;
import com.denimgroup.threadfix.framework.enums.SourceCodeAccessLevel;
import com.denimgroup.threadfix.framework.util.RegexUtils;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

public class JSPDataFlowParser implements ParameterParser {
	
	@Nullable
    private final JSPMappings jspMappings;

    @NotNull
	private final SourceCodeAccessLevel sourceCodeAccessLevel;
	
	private static final Pattern REQUEST_GET_PARAM_STRING_ASSIGN =
			Pattern.compile("^String [^=]+= .*request\\.getParameter\\(\"([^\"]+)\"\\)");
	
	public JSPDataFlowParser(@NotNull ProjectConfig projectConfig) {
		this.sourceCodeAccessLevel = projectConfig.getSourceCodeAccessLevel();
		
		if (projectConfig.getRootFile() != null) {
			jspMappings = new JSPMappings(projectConfig.getRootFile());
		} else {
			jspMappings = null;
		}
	}

	@Override
	public String parse(@NotNull EndpointQuery query) {
		String parameter = null;
		
		if (query.getCodePoints() != null) {
			if (sourceCodeAccessLevel != SourceCodeAccessLevel.FULL) {
				parameter = parseWithSource(query);
			} else {
				parameter = parseNoSource(query);
			}
		}
		
		if (parameter == null) {
			parameter = query.getParameter();
		}
		
		return parameter;
	}
	
	@Nullable
    private String parseNoSource(@NotNull EndpointQuery query) {
		String parameter = null;

        List<CodePoint> codePoints = query.getCodePoints();

        if (codePoints != null) {
            for (CodePoint element : query.getCodePoints()) {
                if (element != null && element.getLineText() != null) {
                    String test = RegexUtils.getRegexResult(element.getLineText(),
                            REQUEST_GET_PARAM_STRING_ASSIGN);
                    if (test != null) {
                        parameter = test;
                    }
                }
            }
        }
	
		return parameter;
	}
	
	@Nullable
    private String parseWithSource(@NotNull EndpointQuery query) {
		String test = null;
		
		if (jspMappings == null) {
			test = parseNoSource(query);
		} else {
			
			String staticInformation = query.getStaticPath();
			
			if (staticInformation == null && query.getCodePoints() != null &&
					query.getCodePoints().size() > 1) {
				staticInformation = query.getCodePoints().get(0).getSourceFileName();
			}
			
			if (staticInformation != null &&
					jspMappings.getEndpoint(staticInformation) != null) {
				JSPEndpoint endpoint = jspMappings.getEndpoint(staticInformation);
				if (endpoint != null) {
					test = endpoint.getParameterName(query.getCodePoints());
				}
			}
			
			// if we didn't get a result, do the dumb regex parsing
			if (test == null) {
				test = parseNoSource(query);
			}
		}
		
		return test;
	}
	
}
