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

import java.io.File;

import org.eclipse.jgit.lib.Repository;

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.service.SanitizedLogger;
import com.denimgroup.threadfix.service.framework.ProjectDirectory;
import com.denimgroup.threadfix.service.framework.ServletMappings;
import com.denimgroup.threadfix.service.framework.WebXMLParser;
import com.denimgroup.threadfix.service.repository.GitService;

public class MergeConfigurationGenerator {
	
	private static final SanitizedLogger log = new SanitizedLogger("MergeConfigurationGenerator");
	
	private static final String baseDirectory = "C:\\test\\scratch\\";
	
	private MergeConfigurationGenerator(){}
	
	public static ScanMergeConfiguration generateConfiguration(Application application, Scan scan) {
		if (application == null) {
			return null;
		}
		
		VulnTypeStrategy typeStrategy = 
				VulnTypeStrategy.getVulnTypeStrategy(application.getVulnTypeStrategy());
		SourceCodeAccessLevel accessLevel = 
				SourceCodeAccessLevel.getSourceCodeAccessLevel(application.getSourceCodeAccessLevel());
		FrameworkType frameworkType = 
				FrameworkType.getFrameworkType(application.getFrameworkType());
		
		log.info("Vulnerability type matching strategy from application: " + typeStrategy.displayName);
		log.info("Source Code Access Level from application: " + accessLevel.displayName);
		log.info("Framework Type from application: " + frameworkType.displayName);
		
		File workTree = null; // optional
		ServletMappings servletMappings = null; //optional
		
		if (accessLevel == SourceCodeAccessLevel.DETECT) {
			accessLevel = guessSourceCodeAccessLevel(application, scan);
		}
		
		if (frameworkType == FrameworkType.DETECT) {
			if (accessLevel == SourceCodeAccessLevel.FULL) {
				workTree = getWorkTree(application);
				if (workTree != null) {
					frameworkType = guessFrameworkTypeFromSourceTree(workTree);
				} else {
					frameworkType = FrameworkType.NONE;
				}
			} else if (accessLevel == SourceCodeAccessLevel.PARTIAL){
				frameworkType = guessFrameworkTypeFromDataFlows(application, scan);
			} else if (accessLevel == SourceCodeAccessLevel.NONE){
				// TODO we can still figure out JSP / ASP / PHP
				frameworkType = FrameworkType.NONE;
				log.info("Framework Type set to None because there was no source code access.");
			}
		}
		
		return new ScanMergeConfiguration(typeStrategy, accessLevel, frameworkType,
				workTree, application.getProjectRoot(), servletMappings);
	}
	
	// TODO cache this information so we don't have to calculate every time
	private static FrameworkType guessFrameworkTypeFromDataFlows(Application application, Scan scan) {
		log.info("Attempting to guess Framework Type from data flows.");
		
		FrameworkType returnType = guessFrameworkType(scan);
		
		if (returnType == FrameworkType.NONE && application != null && application.getScans() != null) {
			for (Scan applicationScan : application.getScans()) {
				FrameworkType scanType = guessFrameworkType(applicationScan);
				if (scanType != FrameworkType.NONE) {
					returnType = scanType;
					break;
				}
			}
		}
		
		log.info("The data flow Framework Type detection returned: " + returnType.displayName);
		
		return returnType;
	}
	
	// TODO improve this 
	private static FrameworkType guessFrameworkType(Scan scan) {
		FrameworkType type = FrameworkType.NONE;
		
		if (scan != null && scan.isStatic() && scan.getFindings() != null &&
				!scan.getFindings().isEmpty()) {
			for (Finding finding : scan.getFindings()) {
				if (finding != null && finding.getStaticPathInformation() != null && 
						finding.getStaticPathInformation().guessFrameworkType() == FrameworkType.SPRING_MVC) {
					type = FrameworkType.SPRING_MVC;
					break;
				} else if (finding != null && finding.getSourceFileLocation() != null &&
						finding.getSourceFileLocation().endsWith(".jsp")) {
					type = FrameworkType.JSP;
					// There is intentionally not a break here. Since Spring projects also contain
					// JSP files sometimes, we only want to use JSP if no Spring hints are found.
				}
			}
		}
		
		return type;
	}

	public static File getWorkTree(Application application) {
		File applicationDirectory = new File(baseDirectory + application.getId());
		
		Repository repo = GitService.cloneGitTreeToDirectory(application.getRepositoryUrl(), applicationDirectory);
		
		if (repo != null && repo.getWorkTree() != null && repo.getWorkTree().exists()) {
			return repo.getWorkTree();
		} else {
			return null;
		}
	}
	
	// For now this is not very general and only handles Java stuff.
	// In the interest of moving on I am going to leave it, but this may need to be re-architected
	// when we add more framework parsers to ThreadFix
	private static FrameworkType guessFrameworkTypeFromSourceTree(File workTree) {
		log.info("Attempting to guess Framework Type from source tree.");
		
		FrameworkType frameworkType = FrameworkType.NONE;
		
		if (workTree != null) {
			File webXML = new ProjectDirectory(workTree).findWebXML();
			if (webXML != null && webXML.exists()) {
				ServletMappings mappings = WebXMLParser.getServletMappings(webXML);
				
				if (mappings != null) {
					frameworkType = mappings.guessApplicationType();
				}
			}
		}
		
		log.info("Source tree framework type detection returned: " + frameworkType.displayName);
		
		return frameworkType;
	}

	public static ScanMergeConfiguration getDefaultConfiguration() {
		return new ScanMergeConfiguration(
				VulnTypeStrategy.EXACT, SourceCodeAccessLevel.DETECT, FrameworkType.DETECT,
				null, null, null);
	}
	
	private static SourceCodeAccessLevel guessSourceCodeAccessLevel(Application application, Scan scan) {
		log.info("Attempting to detect the Source Code Access Level");
		
		SourceCodeAccessLevel returnLevel;
		
		if (application.getRepositoryUrl() != null && !application.getRepositoryUrl().trim().isEmpty()) {
			returnLevel = SourceCodeAccessLevel.FULL;
			log.info("Since there is a configured Repository URL, returning " + returnLevel.displayName);
		} else if (hasStaticScans(application) || (scan != null && scan.isStatic())) {
			returnLevel = SourceCodeAccessLevel.PARTIAL;
			log.info("Since there is at least one static scan in the application, returning " + returnLevel.displayName);
		} else {
			returnLevel = SourceCodeAccessLevel.NONE;
			log.info("Since there was no repository url and there were no static scans, returning " + returnLevel.displayName);
		}
		
		return returnLevel;
	}
	
	private static boolean hasStaticScans(Application application) {
		boolean returnValue = false;
		
		if (application != null && application.getScans() != null && 
				!application.getScans().isEmpty()) {
			for (Scan scan : application.getScans()) {
				if (scan.isStatic()) {
					returnValue = true;
					break;
				}
			}
		}
		
		return returnValue;
	}
}
