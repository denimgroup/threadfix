////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2016 Denim Group, Ltd.
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

import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.framework.engine.ThreadFixInterface;
import com.denimgroup.threadfix.framework.engine.partial.PartialMapping;
import com.denimgroup.threadfix.framework.util.CommonPathFinder;

import java.util.Collections;
import java.util.List;

/**
 * Encapsulates all Finding matching functionality complete with configuration options.
 * TODO improve integration with ScanMergeConfiguration and add SBIR stuff.
 * @author mcollins
 *
 */
public class FindingMatcher {
	
	private final String urlPathRoot;

	private String lowerCaseFilePathRoot = null;
	
	public FindingMatcher(Scan scan) {
		if (scan != null) {
			urlPathRoot = scan.getUrlPathRoot();
            lowerCaseFilePathRoot = scan.getFilePathRoot();

			if (lowerCaseFilePathRoot == null) {
				List<PartialMapping> partialMappings = ThreadFixInterface.toPartialMappingList(scan);

				lowerCaseFilePathRoot = CommonPathFinder.findOrParseProjectRoot(partialMappings);
			}

			if (lowerCaseFilePathRoot != null) {
				lowerCaseFilePathRoot = cleanPathString(lowerCaseFilePathRoot);
			}
		} else {
			urlPathRoot = null;
		}
	}
	
	/**
	 * This method chooses the correct static / dynamic matching algorithm and applies it to
	 * the supplied finding and each finding in the vulnerability.
	 * 
	 */
	public boolean doesMatch(Finding finding, Vulnerability vuln) {
		if (finding == null || vuln == null) {
			return false;
		}

		// iterate through the findings of the vulnerability and try to match
		// them to the finding
		for (Finding vulnFinding : vuln.getFindings()) {
			if (finding.getDependency() == null) {
				if (!finding.getIsStatic()) {
					if (!vulnFinding.getIsStatic() && dynamicToDynamicMatch(finding, vulnFinding)) {
						return true;
					} else if (vulnFinding.getIsStatic() && dynamicToStaticMatch(finding, vulnFinding)) {
						return true;
					}
				} else {
					if (!vulnFinding.getIsStatic() && dynamicToStaticMatch(vulnFinding, finding)) {
						return true;
					} else if (vulnFinding.getIsStatic() && staticToStaticMatch(vulnFinding, finding)) {
						return true;
					}
				}
			} else {
				if (vulnFinding.getDependency() != null && dependencyToDependencyMatch(finding, vulnFinding)) {
					return true;
				}
			}
		}

		return false;
	}

	private boolean dependencyToDependencyMatch(Finding newFinding, Finding oldFinding) {
		return oldFinding != null && newFinding != null &&
				compareDependencyComponent(oldFinding, newFinding) &&
				compareDependencyReference(oldFinding, newFinding);

	}

	private boolean staticToStaticMatch(Finding oldFinding, Finding newFinding) {
		return oldFinding != null && newFinding != null &&
				genericVulnsMatch(oldFinding, newFinding) &&
				compareSurfaceLocationParameter(oldFinding, newFinding) &&
				compareDataFlows(oldFinding, newFinding);
	}

	private boolean dynamicToStaticMatch(Finding dynamicFinding, Finding staticFinding) {
		return dynamicFinding != null && staticFinding != null &&
				genericVulnsMatch(dynamicFinding, staticFinding) &&
				compareStaticAndDynamicPaths(dynamicFinding, staticFinding) &&
				compareSurfaceLocationParameter(dynamicFinding, staticFinding);
	}

	private boolean dynamicToDynamicMatch(Finding newFinding, Finding oldFinding) {
		return newFinding != null && oldFinding != null &&
				genericVulnsMatch(oldFinding, newFinding) &&
				compareSurfaceLocationPaths(oldFinding, newFinding) &&
				compareSurfaceLocationParameter(oldFinding, newFinding);
	}

	private boolean compareStaticAndDynamicPaths(Finding dynamicFinding,
			Finding staticFinding) {
		
		boolean dynamicMatch, staticMatch = false;
		
		dynamicMatch = comparePaths(staticFinding.getCalculatedUrlPath(),
				dynamicFinding.getCalculatedUrlPath());
		
		if (!dynamicMatch) {
			staticMatch = sourceFileNameCompare(dynamicFinding.getCalculatedFilePath(),
					staticFinding.getCalculatedFilePath());
		}
		
		return dynamicMatch || staticMatch;
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
	private boolean compareSurfaceLocationPaths(Finding oldFinding, Finding newFinding) {
		boolean match = false;
		
		if (oldFinding != null && newFinding != null &&
				oldFinding.getSurfaceLocation() != null &&
				newFinding.getSurfaceLocation() != null &&
				oldFinding.getSurfaceLocation().getPath() != null &&
				newFinding.getSurfaceLocation().getPath() != null) {
			match = comparePaths(oldFinding.getCalculatedUrlPath(),
					newFinding.getCalculatedUrlPath());
		}
		
		return match;
	}
	
	private boolean comparePaths(String path1, String path2) {
		boolean returnValue = false;
		
		if (urlPathRoot == null) {
			returnValue = path1 != null && path2 != null && path1.equalsIgnoreCase(path2);
		} else if (path1 != null && path2 != null) {
			returnValue = extractRootPathIfNecessary(path1).equals(extractRootPathIfNecessary(path2));
		}
		
		return returnValue;
	}
	
	private String extractRootPathIfNecessary(String input) {
		if (urlPathRoot != null && input.contains(urlPathRoot)) {
			return input.substring(input.indexOf(urlPathRoot) + urlPathRoot.length());
		} else {
			return input;
		}
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

	private boolean compareDependencyReference(Finding oldFinding, Finding newFinding) {
		return oldFinding.getDependency() != null
				&& newFinding.getDependency() != null
				&& oldFinding.getDependency().getRefId() != null
				&& oldFinding.getDependency().getRefId().equals(newFinding.getDependency().getRefId());
	}

	private boolean compareDependencyComponent(Finding oldFinding, Finding newFinding) {
		return oldFinding.getDependency() != null
				&& newFinding.getDependency() != null
				&& oldFinding.getDependency().getComponentName() != null
				&& oldFinding.getDependency().getComponentName().equals(newFinding.getDependency().getComponentName());
	}

	// package scope for testing
	boolean compareDataFlows(Finding oldFinding, Finding newFinding) {
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
	private boolean sourceFileNameCompare(String oldName, String newName) {
		boolean returnValue;
		
		if (oldName == null || oldName.trim().equals("")
				|| newName == null || newName.equals("")) {
			returnValue = false;
			
		} else {

			// The "cleaning" here returns a standardized slash + downcased string
			String oldPath = cleanPathString(oldName), newPath = cleanPathString(newName);

			// if for some reason cleaning the paths failed, compare the uncleaned
			// paths.
			if (oldPath == null || oldPath.trim().equals("") || newPath == null
					|| newPath.trim().equals("")) {
				returnValue = oldName.equals(newName);
			}
			// if we don't have a project root, or it isn't in one of the paths,
			// return normal comparison of the cleaned strings.
			else if (lowerCaseFilePathRoot == null || lowerCaseFilePathRoot.trim().equals("")
					|| !newPath.contains(lowerCaseFilePathRoot.toLowerCase())) {
				returnValue = oldPath.equals(newPath);
			}
			// if we do have it and it is in both paths, compare the relative paths
			else if (oldPath.contains(lowerCaseFilePathRoot) && newPath.contains(lowerCaseFilePathRoot)) {
				returnValue = oldPath.substring(oldPath.indexOf(lowerCaseFilePathRoot)).equals(
						newPath.substring(newPath.indexOf(lowerCaseFilePathRoot)));
			} else if (newPath.startsWith(lowerCaseFilePathRoot)) {
				// if the old path ends with the same relative old path, it's a match
				returnValue = oldPath.endsWith(newPath.substring(lowerCaseFilePathRoot.length()));
			} else {
				returnValue = false;
			}
		}

		return returnValue;
	}

	// we want to compare strings that have been lowercased, have had
	// their leading / removed, and have / or \ all pointing the same way.
	private String cleanPathString(String inputString) {
		if (inputString == null || inputString.trim().equals("")) {
			return null;
		}
		String outputString = inputString.toLowerCase();

		if (outputString.contains("\\")) {
			outputString = outputString.replace("\\", "/");
		}

		if (outputString.charAt(0) == '/') {
			outputString = outputString.substring(1);
		}

		return outputString;
	}
	
	private boolean genericVulnsMatch(Finding newFinding, Finding oldFinding) {
		boolean match = false;
		
		GenericVulnerability
			newGenericVulnerability = getGenericVulnerability(newFinding),
			oldGenericVulnerability = getGenericVulnerability(oldFinding);
		
		if (newGenericVulnerability != null && oldGenericVulnerability != null) {
			match = newGenericVulnerability.getId().equals(oldGenericVulnerability.getId());
		}
		
		return match;
	}

	private GenericVulnerability getGenericVulnerability(
			Finding finding) {
		if (finding != null && finding.getChannelVulnerability() != null) {
			return finding.getChannelVulnerability().getGenericVulnerability();
		} else {
			return null;
		}
	}

	@Override
	public String toString() {
		return "Matcher " +
				"url='" + urlPathRoot + '\'' +
				" file='" + lowerCaseFilePathRoot + '\'';
	}
}
