package com.denimgroup.threadfix.service.merge;

import java.util.Collections;
import java.util.List;

import com.denimgroup.threadfix.data.entities.ApplicationChannel;
import com.denimgroup.threadfix.data.entities.DataFlowElement;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;

// TODO add the more advanced SBIR methods for finding the project root into here.
public class ProjectRootParser {
	
	private ProjectRootParser(){}
	
	// TODO test this parser on other projects than RiskE
	public static String findOrParseProjectRoot(ApplicationChannel applicationChannel,
			Scan scan) {
		String projectRoot = null;
		
		if (applicationChannel.getApplication() != null
				&& applicationChannel.getApplication().getProjectRoot() != null
				&& !applicationChannel.getApplication().getProjectRoot().trim()
						.equals("")) {
			projectRoot = applicationChannel.getApplication().getProjectRoot()
					.toLowerCase();
		}

		// These next two if statements handle the automatic project root
		// parsing.
		if (projectRoot == null)
			projectRoot = parseProjectRoot(scan);

		return projectRoot;
	}

	static private String parseProjectRoot(Scan scan) {
		if (scan == null || scan.getFindings() == null
				|| scan.getFindings().size() == 0)
			return null;

		String commonPrefix = null;

		for (Finding finding : scan.getFindings()) {
			if (finding.getIsStatic()) {
				List<DataFlowElement> dataFlowElements = finding
						.getDataFlowElements();
				if (dataFlowElements == null || dataFlowElements.size() == 0)
					continue;

				Collections.sort(dataFlowElements);

				if (dataFlowElements.get(0) != null
						&& dataFlowElements.get(0).getSourceFileName() != null) {
					if (commonPrefix == null)
						commonPrefix = dataFlowElements.get(0)
								.getSourceFileName();
					else
						commonPrefix = findCommonPrefix(dataFlowElements.get(0)
								.getSourceFileName(), commonPrefix);
				}
			}
		}

		if (commonPrefix != null && !commonPrefix.equals("")) {
			if (commonPrefix.contains("/")) {
				while (commonPrefix.endsWith("/"))
					commonPrefix = commonPrefix.substring(0,
							commonPrefix.length() - 1);
				if (commonPrefix.contains("/"))
					commonPrefix = commonPrefix.substring(
							commonPrefix.lastIndexOf("/") + 1).replace("/", "");
			}
		}

		return commonPrefix;
	}

	static private String findCommonPrefix(String newString, String oldString) {
		if (newString == null || oldString == null)
			return "";
		if (newString.toLowerCase().contains(oldString.toLowerCase()))
			return oldString;

		String newLower = newString.replace("\\", "/").toLowerCase();
		String oldLower = oldString.replace("\\", "/").toLowerCase();

		String returnString = "";

		for (String string : oldLower.split("/")) {
			String tempString = returnString.concat(string + "/");
			if (newLower.startsWith(tempString))
				returnString = tempString;
			else
				break;
		}

		return oldString.replace("\\", "/").substring(0, returnString.length());
	}
}
