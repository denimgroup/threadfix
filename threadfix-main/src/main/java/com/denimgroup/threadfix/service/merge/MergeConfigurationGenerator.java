package com.denimgroup.threadfix.service.merge;

import java.io.File;

import org.eclipse.jgit.lib.Repository;

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.service.framework.ProjectDirectory;
import com.denimgroup.threadfix.service.framework.ServletMappings;
import com.denimgroup.threadfix.service.framework.WebXMLParser;
import com.denimgroup.threadfix.service.repository.GitService;

public class MergeConfigurationGenerator {
	
	private static final String baseDirectory = "C:\\test\\scratch\\";
	
	private MergeConfigurationGenerator(){}
	
	public static ScanMergeConfiguration generateConfiguration(Application application, Scan scan) {
		if (application == null) {
			return null;
		}
		
		VulnTypeStrategy typeStrategy     = application.getTypeStrategy();
		SourceCodeAccessLevel accessLevel = application.getSourceCodeAccessLevel();
		FrameworkType frameworkType       = application.getFrameworkType();
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
				frameworkType = FrameworkType.NONE;
			}
		}
		
		return new ScanMergeConfiguration(typeStrategy, accessLevel, frameworkType,
				workTree, application.getProjectRoot(), servletMappings);
	}
	
	// TODO cache this information so we don't have to calculate every time
	private static FrameworkType guessFrameworkTypeFromDataFlows(Application application, Scan scan) {
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
		
		return frameworkType;
	}

	public static ScanMergeConfiguration getDefaultConfiguration() {
		return new ScanMergeConfiguration(
				VulnTypeStrategy.EXACT, SourceCodeAccessLevel.DETECT, FrameworkType.DETECT,
				null, null, null);
	}
	
	private static SourceCodeAccessLevel guessSourceCodeAccessLevel(Application application, Scan scan) {
		if (application.getRepositoryUrl() != null && !application.getRepositoryUrl().trim().isEmpty()) {
			return SourceCodeAccessLevel.FULL;
		} else if (hasStaticScans(application) || (scan != null && scan.isStatic())) {
			return SourceCodeAccessLevel.PARTIAL;
		} else {
			return SourceCodeAccessLevel.NONE;
		}
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
