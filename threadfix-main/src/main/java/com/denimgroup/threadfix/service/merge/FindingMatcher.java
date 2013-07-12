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
package com.denimgroup.threadfix.service.merge;

import java.util.Collections;
import java.util.List;

import com.denimgroup.threadfix.data.entities.DataFlowElement;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.GenericVulnerability;
import com.denimgroup.threadfix.data.entities.Vulnerability;

/**
 * Encapsulates all Finding matching functionality complete with configuration options.
 * TODO improve integration with ScanMergeConfiguration and add SBIR stuff.
 * @author mcollins
 *
 */
public class FindingMatcher {
	
	private final String projectRoot;
	private final ScanMergeConfiguration scanMergeConfiguration;
	
	public FindingMatcher(ScanMergeConfiguration scanMergeConfiguration) {
		this.projectRoot = scanMergeConfiguration.getApplicationRoot();
		this.scanMergeConfiguration = scanMergeConfiguration;
	}
	
	/**
	 * This method chooses the correct static / dynamic matching algorithm and applies it to
	 * the supplied finding and each finding in the vulnerability. 
	 * 
	 */
	public boolean doesMatch(Finding finding, Vulnerability vuln) {
		if (finding == null || vuln == null)
			return false;

		// iterate through the findings of the vulnerability and try to match
		// them to the finding
		for (Finding vulnFinding : vuln.getFindings()) {
			if (!finding.getIsStatic()) {
				if (!vulnFinding.getIsStatic()     && dynamicToDynamicMatch(finding, vulnFinding))
					return true;
				else if (vulnFinding.getIsStatic() && dynamicToStaticMatch(finding, vulnFinding))
					return true;
			} else if (finding.getIsStatic()) {
				if (!vulnFinding.getIsStatic()     && dynamicToStaticMatch(vulnFinding, finding))
					return true;
				else if (vulnFinding.getIsStatic() && staticToStaticMatch(finding, vulnFinding))
					return true;
			}
		}

		return false;
	}

	private boolean staticToStaticMatch(Finding oldFinding, Finding newFinding) {
		return oldFinding != null && newFinding != null &&
				genericVulnsMatch(oldFinding, newFinding) &&
				compareSurfaceLocationParameter(oldFinding, newFinding) &&
				compareDataFlows(oldFinding, newFinding);
	}

	private boolean dynamicToStaticMatch(Finding dynamicFinding, Finding staticFinding) {
		return dynamicFinding == null || staticFinding == null && 
				genericVulnsMatch(dynamicFinding, staticFinding) &&
				compareSurfaceLocationPath(dynamicFinding, staticFinding) &&
				compareSurfaceLocationParameter(dynamicFinding, staticFinding);
	}

	private boolean dynamicToDynamicMatch(Finding newFinding, Finding oldFinding) {
		return newFinding != null && oldFinding != null &&
				genericVulnsMatch(oldFinding, newFinding) &&
				compareSurfaceLocationPath(oldFinding, newFinding) &&
				compareSurfaceLocationParameter(oldFinding, newFinding);
	}
	
	// check for exact path match
	// TODO add configuration to this
	// TODO I took out this from staticToDynamicMatch -> need to add it back
	/*
	if (dynamicPath != null && !dynamicPath.startsWith("/"))
		dynamicPath = "/" + dynamicPath;
	if (staticPath != null && !staticPath.startsWith("/"))
		staticPath  = "/" + staticPath;
	 */
	private boolean compareSurfaceLocationPath(Finding oldFinding, Finding newFinding) {
		boolean match = true;
		
		if (oldFinding != null && newFinding != null &&
				oldFinding.getSurfaceLocation() != null &&
				newFinding.getSurfaceLocation() != null &&
				oldFinding.getSurfaceLocation().getPath() != null &&
				newFinding.getSurfaceLocation().getPath() != null) {
			
			switch (scanMergeConfiguration.getSourceCodeAccessLevel()) {
				case FULL:   // TODO
				case PARTIAL:    // TODO
				default:
					match = oldFinding.getSurfaceLocation().getPath().equals(
							newFinding.getSurfaceLocation().getPath());
			}
		}
		
		return match;
	}
	
	// check to see that the parameters match or are both empty
	private boolean compareSurfaceLocationParameter(Finding oldFinding, Finding newFinding) {
		boolean match = false;
		
		if (oldFinding != null && newFinding != null &&
				oldFinding.getSurfaceLocation() != null &&
				newFinding.getSurfaceLocation() != null) {
			
			if (oldFinding.getSurfaceLocation().getParameter() != null &&
				newFinding.getSurfaceLocation().getParameter() != null && 
				oldFinding.getSurfaceLocation().getParameter().equals(
						newFinding.getSurfaceLocation().getParameter())) {
				match = true;
			} else if (oldFinding.getSurfaceLocation().getParameter() == null &&
				newFinding.getSurfaceLocation().getParameter() == null) {
				match = true;
			}
		}
		
		return match;
	}

	private boolean compareDataFlows(Finding oldFinding, Finding newFinding) {
		boolean match = false;
		
		if (oldFinding != null && newFinding != null &&
				oldFinding.getDataFlowElements() != null &&
				newFinding.getDataFlowElements() != null &&
				!oldFinding.getDataFlowElements().isEmpty() &&
				!newFinding.getDataFlowElements().isEmpty()) {
			
			List<DataFlowElement> 
				oldDataFlowElements = oldFinding.getDataFlowElements(),
				newDataFlowElements = newFinding.getDataFlowElements();
			
			Collections.sort(oldDataFlowElements);
			Collections.sort(newDataFlowElements);
			
			// Compare sources
			match = compareDataFlowElements(oldDataFlowElements.get(0),
					newDataFlowElements.get(0));
			
			// If necessary, compare sinks
			if (match && (oldDataFlowElements.size() > 0 || newDataFlowElements.size() > 0)) {
				match = compareDataFlowElements(
						oldDataFlowElements.get(oldDataFlowElements.size() - 1),
						newDataFlowElements.get(newDataFlowElements.size() - 1));
			}
		}
		
		return match;
	}
	
	// Not all dataFlowElements have Column Numbers, and the default is 0,
	// so it is hard to do a meaningful comparison with that data. Plus, we
	// compared variables before starting the rest of the static-static
	// comparison.
	// TODO look at changing this comparison
	private boolean compareDataFlowElements(DataFlowElement oldElement,
			DataFlowElement newElement) {
		return oldElement != null && newElement != null &&
				oldElement.getLineNumber() == newElement.getLineNumber() &&
				sourceFileNameCompare(oldElement.getSourceFileName(), newElement.getSourceFileName());
	}

	// Compare the relative paths according to the application's projectRoot
	// variable.
	private boolean sourceFileNameCompare(String fileName1, String fileName2) {
		if (fileName1 == null || fileName1.trim().equals("")
				|| fileName2 == null || fileName2.equals(""))
			return false;

		String path1 = cleanPathString(fileName1);
		String path2 = cleanPathString(fileName2);

		// if for some reason cleaning the paths failed, compare the uncleaned
		// paths.
		if (path1 == null || path1.trim().equals("") || path2 == null
				|| path2.trim().equals(""))
			return fileName1.equals(fileName2);

		// if we don't have a project root, or it isn't in one of the paths,
		// return normal comparison of the cleaned strings.
		if (projectRoot == null || projectRoot.trim().equals("")
				|| !path1.contains(projectRoot) || !path2.contains(projectRoot))
			return path1.equals(path2);

		// if we do have it and it is in both paths, compare the relative paths
		if (path1.contains(projectRoot) && path2.contains(projectRoot)) {
			return path1.substring(path1.indexOf(projectRoot)).equals(
					path2.substring(path2.indexOf(projectRoot)));
		}

		return false;
	}

	// we want to compare strings that have been lowercased, have had
	// their leading / removed, and have / or \ all pointing the same way.
	private String cleanPathString(String inputString) {
		if (inputString == null || inputString.trim().equals(""))
			return null;
		String outputString = inputString.toLowerCase();

		if (outputString.contains("\\"))
			outputString = outputString.replace("\\", "/");

		if (outputString.charAt(0) == '/')
			outputString = outputString.substring(1);

		return outputString;
	}
	
	private boolean genericVulnsMatch(Finding newFinding, Finding oldFinding) {
		boolean match = false;
		
		GenericVulnerability 
			newGenericVulnerability = getGenericVulnerability(newFinding),
			oldGenericVulnerability = getGenericVulnerability(oldFinding);
		
		if (newGenericVulnerability != null && oldGenericVulnerability != null) {
			switch (scanMergeConfiguration.getTypeStrategy()) {
				case TREES:         
					match = cweTreeMatch(newGenericVulnerability, oldGenericVulnerability);
					break;
				case FAULT_PATTERN: 
					match = faultPatternMatch(newGenericVulnerability, oldGenericVulnerability);
					break;
				default:
					match = newGenericVulnerability.getId().equals(oldGenericVulnerability.getId());
			}
		}
		
		return match;
	}
	
	private boolean cweTreeMatch(
			GenericVulnerability newGenericVulnerability,
			GenericVulnerability oldGenericVulnerability) {
		// TODO Auto-generated method stub
		return false;
	}

	private boolean faultPatternMatch(
			GenericVulnerability newGenericVulnerability,
			GenericVulnerability oldGenericVulnerability) {
		// TODO Auto-generated method stub
		return false;
	}

	private GenericVulnerability getGenericVulnerability(
			Finding finding) {
		if (finding != null && finding.getChannelVulnerability() != null) {
			return finding.getChannelVulnerability().getGenericVulnerability();
		} else {
			return null;
		}
	}
	
}
