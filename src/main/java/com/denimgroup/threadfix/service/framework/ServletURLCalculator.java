package com.denimgroup.threadfix.service.framework;

import java.io.File;
import java.util.List;

import com.denimgroup.threadfix.data.entities.DataFlowElement;
import com.denimgroup.threadfix.data.entities.Finding;

public class ServletURLCalculator extends AbstractURLCalculator {

	public ServletURLCalculator(ServletMappings mappings, File workTree) {
		super(mappings, workTree);
	}

	@Override
	public boolean findMatch(Finding finding)  {
		if (finding == null || mappings == null) {
			return false;
		}
		
		boolean result = false;
		
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
		String returnName = element.getSourceFileName();
		if (returnName.contains("\\")) {
			returnName = returnName.replace('\\', '/');
		}
		
		returnName = returnName.replace('/', '.');
		if (returnName.contains("java")) {
			returnName = returnName.substring(returnName.indexOf("java") + 4);
		}
		
		if (returnName.charAt(0) == '.') {
			returnName = returnName.substring(1);
		}
		
		if (returnName.endsWith(".java")) {
			returnName = returnName.substring(0, returnName.length() - 5);
		}
		
		return returnName;
		
	}
}
