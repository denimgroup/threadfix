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
import com.denimgroup.threadfix.service.merge.ScanMergeConfiguration;
import com.denimgroup.threadfix.service.merge.SourceCodeAccessLevel;

public class JSPDataFlowParser implements ParameterParser {
	
	private final JSPMappings jspMappings;
	private final ScanMergeConfiguration scanMergeConfiguration;
	
	private static final Pattern REQUEST_GET_PARAM_STRING_ASSIGN =
			Pattern.compile("^String [^=]+= .*request\\.getParameter\\(\"([^\"]+)\"\\)");
	
	public JSPDataFlowParser(JSPMappings jspMappings, ScanMergeConfiguration scanMergeConfiguration) {
		this.jspMappings = jspMappings;
		this.scanMergeConfiguration = scanMergeConfiguration;
	}

	@Override
	public String parse(Finding finding) {
		String parameter = null;
		
		if (finding != null && finding.getDataFlowElements() != null) {
			if (scanMergeConfiguration != null && 
					scanMergeConfiguration.getSourceCodeAccessLevel() != SourceCodeAccessLevel.FULL) {
				parameter = parseWithSource(finding);
			} else {
				parameter = parseNoSource(finding);
			}
		}
		
		if (parameter == null && finding != null && finding.getSurfaceLocation() != null) {
			parameter = finding.getSurfaceLocation().getParameter();
		}
		
		return parameter;
	}
	
	private String parseNoSource(Finding finding) {
		String parameter = null;
		
		for (DataFlowElement element : finding.getDataFlowElements()) {
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
	
	private String parseWithSource(Finding finding) {
		String test = null;
		
		boolean missingMappings = false;
		
		if (jspMappings == null) {
			test = parseNoSource(finding);
		} else {
			for (DataFlowElement element : finding.getDataFlowElements()) {
				if (jspMappings.getParameterMap(element.getSourceFileName()) != null) {
					List<String> possibleParameters = jspMappings
							.getParameterMap(element.getSourceFileName())
							.get(element.getLineNumber());
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
			test = parseNoSource(finding);
		}
		
		return test;
	}
	
}
