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

import com.denimgroup.threadfix.data.entities.DataFlowElement;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.service.merge.ScanMergeConfiguration;

public class ServletTranslator extends AbstractPathUrlTranslator {

	public ServletTranslator(ScanMergeConfiguration scanMergeConfiguration, Scan scan) {
		super(scanMergeConfiguration, scan);
	}

	public boolean findMatch(Finding finding)  {
		if (finding == null || mappings == null) {
			return false;
		}
		
		boolean result = false;
		
		// TODO only works for static findings.
		
		for (DataFlowElement element : finding.getDataFlowElements()) {
			String newPackageName = getPackageName(element);
			List<String> results = mappings.getURLPatternsForClass(newPackageName);
			if (results != null && results.size() > 0) {
				System.out.println(results);
				result = true;
			} else {
//				System.out.println(newPackageName + " didn't match any of " + webGoat.getClassMappings());
			}
		}
		
		return result;
	}
	
	private static String getPackageName(DataFlowElement element) {
		
		String returnName = null;
		
		if (element != null && element.getSourceFileName() != null && 
				element.getSourceFileName().length() > 0) {
			returnName = element.getSourceFileName();
	
			if (returnName.contains("\\")) {
				returnName = returnName.replace('\\', '/');
			}
			
			returnName = returnName.replace('/', '.');
			if (returnName.contains("java")) {
				returnName = returnName.substring(returnName.indexOf("java") + 4);
			}
			
			if (returnName.length() > 0 && returnName.charAt(0) == '.') {
				returnName = returnName.substring(1);
			}
			
			if (returnName.endsWith(".java")) {
				returnName = returnName.substring(0, returnName.length() - 5);
			}
		}
		return returnName;
	}

	@Override
	public String getFileName(Finding dynamicFinding) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getUrlPath(Finding staticFinding) {
		// TODO Auto-generated method stub
		return null;
	}
}
